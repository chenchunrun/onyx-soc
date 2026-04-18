# Dependency updates (when subchart versions are bumped)
* If updating subcharts, you need to run this before committing!
* cd charts/onyx
* helm dependency update .

# Local testing

## One time setup
* brew install kind
* Ensure you have no config at ~/.kube/config
* kind create cluster
* mv ~/.kube/config ~/.kube/kind-config

## Automated install and test with ct
* export KUBECONFIG=~/.kube/kind-config
* kubectl config use-context kind-kind
* from source root run the following. This does a very basic test against the web server
  * ct install --all --helm-extra-set-args="--set=nginx.enabled=false" --debug --config ct.yaml

## Output template to file and inspect
* cd charts/onyx
* helm template test-output . --set auth.opensearch.values.opensearch_admin_password='StrongPassword123!' > test-output.yaml

## Test the entire cluster manually
* cd charts/onyx
* helm install onyx . -n onyx --set postgresql.primary.persistence.enabled=false --set auth.opensearch.values.opensearch_admin_password='StrongPassword123!'
  * the postgres flag is to keep the storage ephemeral for testing. You probably don't want to set that in prod.
  * the OpenSearch admin password must be set on first install unless you are supplying `auth.opensearch.existingSecret`.
  * no flag for ephemeral vespa storage yet, might be good for testing
* kubectl -n onyx port-forward service/onyx-nginx 8080:80
  * this will forward the local port 8080 to the installed chart for you to run tests, etc.
* When you are finished
  * helm uninstall onyx -n onyx
  * Vespa leaves behind a PVC. Delete it if you are completely done.
    * k -n onyx get pvc
    * k -n onyx delete pvc vespa-storage-da-vespa-0
  * If you didn't disable Postgres persistence earlier, you may want to delete that PVC too.

## Security platform overlay
If you are deploying the security-platform customization from `knowledge-base/`,
you can layer the provided example values file on top of the base chart values:

```bash
cd charts/onyx
helm upgrade --install onyx . -n onyx --create-namespace \
  -f values.yaml \
  -f values.security-platform.yaml
```

The overlay adds example env vars and secret mappings for:
- `SECURITY_ALERT_WEBHOOK_URL`
- `SECURITY_TICKET_API_URL`
- `SECURITY_TICKET_API_KEY`
- `THREAT_INTEL_API_URL`
- `THREAT_INTEL_API_KEY`

After the chart is deployed, run the bootstrap and verification steps described
in `docs/security-platform/7-deployment.md`.

### Threat-intel scheduled sync

Threat-intel periodic sync is currently executed as an external operations job.
Use the repo helper script from an ops runner, CI job, or bastion host that can
reach the deployed Onyx endpoint:

```bash
bash deployment/scripts/run_security_platform_threat_intel_sync.sh
```

Provide `ONYX_URL`, `ONYX_EMAIL`, `ONYX_PASSWORD`, and optional
`THREAT_INTEL_SYNC_LIMIT` / `THREAT_INTEL_SOURCE_PROFILE` via environment variables before invoking it.

## Custom image registry
The chart now supports a global image registry override for all Onyx-owned images.
This lets you keep using the upstream chart while pulling backend, web, and model images
from your own registry.

Example:

```yaml
global:
  imageRegistry: registry.example.com
  images:
    backendRepository: platform/onyx-backend
    webRepository: platform/onyx-web-server
    modelRepository: platform/onyx-model-server
```

Apply it with:

```bash
cd charts/onyx
helm upgrade --install onyx . -n onyx --create-namespace \
  -f values.yaml \
  -f my-registry-overrides.yaml
```

If you need per-component exceptions, set `image.repository` for the specific component in your override file.

### Dependency mirror note
This chart still depends on several external chart repositories. Two of them are Onyx-maintained:
- `https://onyx-dot-app.github.io/vespa-helm-charts`
- `https://onyx-dot-app.github.io/python-sandbox/`

If you want a fully self-managed Helm supply chain, you need to mirror those chart repositories yourself
and then update both `Chart.yaml` and `Chart.lock` to point at your mirrored endpoints before running
`helm dependency update`.

## Run as non-root user
By default, some onyx containers run as root. If you'd like to explicitly run the onyx containers as a non-root user, update the values.yaml file for the following components:
  * `celery_shared`, `api`, `webserver`, `indexCapability`, `inferenceCapability`
    ```yaml
    securityContext:
      runAsNonRoot: true
      runAsUser: 1001
    ```
  * `vespa`
    ```yaml
    podSecurityContext:
      fsGroup: 1000
    securityContext:
      privileged: false
      runAsUser: 1000
    ```

## Resourcing
In the helm charts, we have resource suggestions for all Onyx-owned components. 
These are simply initial suggestions, and may need to be tuned for your specific use case.

If you have questions about these values, route them through your local platform owner or repository issue tracker.

## Autoscaling options
The chart renders Kubernetes HorizontalPodAutoscalers by default. To keep this behavior, leave
`autoscaling.engine` as `hpa` and adjust the per-component `autoscaling.*` values as needed.

If you would like to use KEDA ScaledObjects instead:

1. Install and manage the KEDA operator in your cluster yourself (for example via the official KEDA Helm chart). KEDA is no longer packaged as a dependency of the Onyx chart.
2. Set `autoscaling.engine: keda` in your `values.yaml` and enable autoscaling for the components you want to scale.

When `autoscaling.engine` is set to `keda`, the chart will render the existing ScaledObject templates; otherwise HPAs will be rendered.
