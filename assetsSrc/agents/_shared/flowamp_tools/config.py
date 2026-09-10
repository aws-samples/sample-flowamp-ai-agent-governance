# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Shared AppConfig retrieval utility for all FlowAMP agents and Lambdas.

Fetches model configuration from AWS AppConfig on first use and caches the parsed JSON
for the life of the execution context, so warm invocations make no network call.

Required environment variables:
  AWS_REGION            — AWS region for the appconfigdata client
  APPCONFIG_APP_ID      — AppConfig application ID (injected by CDK stack)
  APPCONFIG_ENV_ID      — AppConfig environment ID (injected by CDK stack)
  APPCONFIG_PROFILE_ID  — AppConfig configuration profile ID (injected by CDK stack)

Required config fields (startup raises ValueError if any are absent):
  defaultModel
  complianceScannerModel
  discoveryEnrichmentModel
  evaluationSummaryModel
"""
import json
import os
import boto3

_REQUIRED_FIELDS = (
    "defaultModel",
    "complianceScannerModel",
    "discoveryEnrichmentModel",
    "evaluationSummaryModel",
)

_config_cache: dict | None = None


_LOCAL_DEFAULT_CONFIG = {
    "defaultModel": "us.anthropic.claude-sonnet-5",
    "complianceScannerModel": "us.anthropic.claude-sonnet-5",
    # Every key names the same model. `modelInvokeStatement` in team-stack.ts grants the
    # runtimes any inference profile in this account but only one foundation-model ARN,
    # the configured base model, and invoking through a profile also authorizes against
    # the underlying model - so a second model family would be denied.
    "discoveryEnrichmentModel": "us.anthropic.claude-sonnet-5",
    # Unreferenced by any shipped code path; kept so a future evaluation summariser has
    # a configured model rather than hardcoding one.
    "evaluationSummaryModel": "us.anthropic.claude-sonnet-5",
}


def get_model_config() -> dict:
    """Return the cached model configuration dict, fetching from AppConfig on first call.

    When ENVIRONMENT=local, returns a hardcoded default config so agents can start
    without AppConfig infrastructure.

    Raises RuntimeError  if AppConfig returns an empty payload.
    Raises ValueError    if a required field is missing from the configuration.
    Raises EnvironmentError if a required environment variable is absent.
    """
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    if os.environ.get("ENVIRONMENT") == "local":
        _config_cache = _LOCAL_DEFAULT_CONFIG.copy()
        return _config_cache

    region = os.environ.get("AWS_REGION")
    if not region:
        raise EnvironmentError(
            "AWS_REGION is not set. "
            "This variable must be injected by the Lambda/AgentCore infrastructure."
        )

    app_id = os.environ.get("APPCONFIG_APP_ID")
    if not app_id:
        raise EnvironmentError(
            "APPCONFIG_APP_ID is not set. "
            "This variable must be injected by the Lambda/AgentCore infrastructure."
        )

    env_id = os.environ.get("APPCONFIG_ENV_ID")
    if not env_id:
        raise EnvironmentError(
            "APPCONFIG_ENV_ID is not set. "
            "This variable must be injected by the Lambda/AgentCore infrastructure."
        )

    profile_id = os.environ.get("APPCONFIG_PROFILE_ID")
    if not profile_id:
        raise EnvironmentError(
            "APPCONFIG_PROFILE_ID is not set. "
            "This variable must be injected by the Lambda/AgentCore infrastructure."
        )

    client = boto3.client("appconfigdata", region_name=region)

    token_resp = client.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_id,
        RequiredMinimumPollIntervalInSeconds=30,
    )

    config_resp = client.get_latest_configuration(
        ConfigurationToken=token_resp["InitialConfigurationToken"]
    )

    content = config_resp["Configuration"].read()
    if not content:
        raise RuntimeError(
            "AppConfig returned an empty configuration. "
            "Ensure an initial deployment exists for the model-ids profile."
        )

    parsed = json.loads(content)

    for field in _REQUIRED_FIELDS:
        if field not in parsed:
            raise ValueError(
                f"AppConfig configuration missing required field: {field}. "
                f"Present fields: {list(parsed.keys())}"
            )

    _config_cache = parsed
    return _config_cache


def _clear_config_cache() -> None:
    """Reset the in-process cache. Used in tests to avoid state leakage between cases."""
    global _config_cache
    _config_cache = None
