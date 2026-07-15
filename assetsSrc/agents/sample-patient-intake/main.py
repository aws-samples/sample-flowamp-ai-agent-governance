"""Sample workload: Healthcare Patient-Intake Assistant.

A standalone Strands agent deployed on Amazon Bedrock AgentCore Runtime. It
structures free-text patient intake notes, assigns a triage urgency level, and
routes the encounter to an appropriate department.

IMPORTANT: This agent performs intake structuring and routing ONLY. It does NOT
provide medical diagnosis, treatment advice, or clinical decisions. All triage
output is administrative and must be confirmed by a licensed clinician.

This is an independent sample agent (not part of the FlowAMP control plane) so
that the FlowAMP governance platform can discover, classify, and govern it as a
real deployed workload. All data returned by the tools below is synthetic and
illustrative; a customer swaps in real EHR and clinical-triage integrations.

RESPONSIBLE USE: This is an illustrative sample for demonstration only, not a
production decision-making system. Its output is administrative intake
structuring and must not be used as medical advice, diagnosis, or clinical
triage. Production deployments in this regulated domain should attach an Amazon
Bedrock Guardrail (set guardrailId/guardrailVersion on the BedrockModel) and keep
a licensed clinician in the loop for all clinical decisions.
"""
# ---------------------------------------------------------------------------
# OTEL bootstrap — must run before any other import (boto3, strands, etc.).
#
# OpenTelemetry auto-instrumentation is enabled by launching the agent under the
# `opentelemetry-instrument` wrapper, which reads the OTEL_*/
# AGENT_OBSERVABILITY_ENABLED env vars and installs the global TracerProvider and
# OTLP exporter wired to aws/spans. See the AWS docs
# (bedrock-agentcore/observability-configure §"Enabling observability in agent
# code for AgentCore-hosted agents"). AgentCore direct-code deploy launches
# `python main.py` directly, so the agent re-execs itself under
# auto-instrumentation at startup to enable span export.
#
# The re-exec runs the container's interpreter and calls the wrapper's public
# entry point, opentelemetry.instrumentation.auto_instrumentation.run(), which is
# importable from the vendored packages in the bundle root. The _OTEL_REEXEC
# guard makes this one-shot. It is gated on AGENT_OBSERVABILITY_ENABLED so local
# runs are unaffected, and any failure is swallowed so a missing wrapper never
# crashes the agent.
import os as _os
import sys as _sys

if (
    _os.environ.get("AGENT_OBSERVABILITY_ENABLED") == "true"
    and not _os.environ.get("_OTEL_REEXEC")
):
    _os.environ["_OTEL_REEXEC"] = "1"
    _bundle_dir = _os.path.dirname(_os.path.abspath(__file__))
    _os.environ["PYTHONPATH"] = (
        _bundle_dir + _os.pathsep + _os.environ.get("PYTHONPATH", "")
    ).rstrip(_os.pathsep)
    try:
        # Safe: the exec target and argv are the process's own trusted values
        # (sys.executable, sys.argv) — no external/user input reaches this call.
        # It only re-launches this same script under OpenTelemetry auto-instrumentation.
        _os.execv(  # nosemgrep: dangerous-os-exec-tainted-env-args,dangerous-os-exec-audit
            _sys.executable,
            [
                _sys.executable,
                "-c",
                "from opentelemetry.instrumentation.auto_instrumentation import run; run()",
                _sys.executable,
                *_sys.argv,
            ],
        )
    except Exception as _reexec_exc:  # noqa: BLE001
        print(f"otel auto-instrument re-exec skipped: {_reexec_exc}")

import os
import json
import re
from strands import Agent, tool
from strands.models.bedrock import BedrockModel


# Illustrative symptom lexicon and department mapping. A production deployment
# would use a validated clinical NLP model and a hospital's department registry.
_SYMPTOM_LEXICON = {
    'chest pain': 'cardiac', 'shortness of breath': 'respiratory',
    'difficulty breathing': 'respiratory', 'fever': 'infection',
    'headache': 'neuro', 'dizziness': 'neuro', 'numbness': 'neuro',
    'abdominal pain': 'gastro', 'nausea': 'gastro', 'vomiting': 'gastro',
    'rash': 'derm', 'cough': 'respiratory', 'fatigue': 'general',
    'bleeding': 'trauma', 'fracture': 'trauma', 'swelling': 'general',
    'sore throat': 'general', 'back pain': 'ortho', 'joint pain': 'ortho',
}
# Symptoms that indicate a possible emergency and warrant immediate routing.
_RED_FLAGS = ('chest pain', 'shortness of breath', 'difficulty breathing',
              'bleeding', 'numbness', 'confusion', 'unconscious', 'seizure')
_DEPARTMENT_LABELS = {
    'cardiac': 'Cardiology', 'respiratory': 'Pulmonology', 'infection': 'Internal Medicine',
    'neuro': 'Neurology', 'gastro': 'Gastroenterology', 'derm': 'Dermatology',
    'trauma': 'Emergency Department', 'ortho': 'Orthopedics', 'general': 'General Medicine',
}


@tool
def extract_symptoms(intake_notes: str) -> str:
    """Extract a structured list of symptoms from free-text intake notes.

    Args:
        intake_notes: The free-text notes captured at patient intake.
    """
    lowered = (intake_notes or '').lower()
    found = []
    for phrase, category in _SYMPTOM_LEXICON.items():
        if phrase in lowered:
            found.append({'symptom': phrase, 'category': category})

    # Best-effort age/duration capture for downstream context.
    age_match = re.search(r'(\d{1,3})\s*(?:yo|y/o|years old|year old)', lowered)
    duration_match = re.search(r'(\d+)\s*(hour|day|week|month)s?', lowered)

    return json.dumps({
        'symptoms': found,
        'symptomCount': len(found),
        'reportedAge': int(age_match.group(1)) if age_match else None,
        'reportedDuration': (duration_match.group(0) if duration_match else None),
        'note': 'Extraction is administrative only; not a clinical assessment.',
    }, default=str)


@tool
def check_urgency(symptom_list: str) -> str:
    """Assign an administrative triage urgency level for a set of symptoms.

    Args:
        symptom_list: A comma-separated or free-text list of symptoms.
    """
    lowered = (symptom_list or '').lower()
    red_flags = [flag for flag in _RED_FLAGS if flag in lowered]
    distinct = [phrase for phrase in _SYMPTOM_LEXICON if phrase in lowered]

    if red_flags:
        level = 'emergent'
        target_minutes = 15
    elif len(distinct) >= 3:
        level = 'urgent'
        target_minutes = 60
    elif distinct:
        level = 'semi-urgent'
        target_minutes = 240
    else:
        level = 'non-urgent'
        target_minutes = 1440

    return json.dumps({
        'triageLevel': level,
        'redFlagSymptoms': red_flags,
        'targetTimeToClinicianMinutes': target_minutes,
        'requiresImmediateClinicianReview': bool(red_flags),
        'disclaimer': 'Administrative triage only. A licensed clinician must confirm.',
    }, default=str)


@tool
def suggest_department(symptom_summary: str) -> str:
    """Suggest a routing department based on a symptom summary.

    Args:
        symptom_summary: A short summary of the patient's symptoms.
    """
    lowered = (symptom_summary or '').lower()
    scores = {}
    for phrase, category in _SYMPTOM_LEXICON.items():
        if phrase in lowered:
            scores[category] = scores.get(category, 0) + 1

    if any(flag in lowered for flag in _RED_FLAGS):
        category = 'trauma'
    elif scores:
        category = max(scores, key=scores.get)
    else:
        category = 'general'

    return json.dumps({
        'recommendedDepartment': _DEPARTMENT_LABELS.get(category, 'General Medicine'),
        'departmentCode': category,
        'alternates': [_DEPARTMENT_LABELS[c] for c in scores if c != category],
        'disclaimer': 'Routing suggestion only; not a diagnosis. Clinician confirms placement.',
    }, default=str)


model = BedrockModel(model_id="us.anthropic.claude-sonnet-4-6")

agent = Agent(
    model=model,
    tools=[extract_symptoms, check_urgency, suggest_department],
    system_prompt="""You are a healthcare patient-intake assistant.
Your job is strictly administrative: you structure free-text intake notes into
a list of symptoms, assign a triage urgency level, and route the patient to an
appropriate department.
You do NOT provide medical diagnosis, treatment recommendations, or clinical
advice of any kind. Always state that your output is administrative triage and
routing only, and that a licensed clinician must review and confirm.
Always use the available tools to structure the intake before responding, and
escalate any red-flag symptoms for immediate clinician review.

IMPORTANT: This is an illustrative sample for demonstration only. Output is
administrative intake structuring — NOT medical advice, diagnosis, or triage. A
licensed clinician must review and make all clinical decisions.""",
)


def handler(event, context):
    """HTTP handler for AgentCore Runtime."""
    body = json.loads(event.get('body', '{}')) if isinstance(event.get('body'), str) else event.get('body', {})
    prompt = body.get('prompt', body.get('message', ''))
    if not prompt:
        return {'statusCode': 400, 'body': json.dumps({'error': 'No prompt provided'})}

    result = agent(prompt)
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'response': str(result)})
    }


if __name__ == '__main__':
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            result = handler({'body': body}, None)
            self.send_response(result['statusCode'])
            for k, v in result.get('headers', {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(result['body'].encode())

    port = int(os.environ.get('PORT', '8080'))
    # Bind host is configurable. Inside the AgentCore container the runtime must
    # reach the server, so this defaults to all interfaces; set BIND_HOST to a
    # specific address to restrict it.
    host = os.environ.get('BIND_HOST', '0.0.0.0')  # nosec B104 - container-internal server, host is configurable
    print(f"Starting agent on {host}:{port}")
    HTTPServer((host, port), Handler).serve_forever()
