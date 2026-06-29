# **SIEM Ingestion Pipeline**


This is a production-style data pipeline built in Python. It pulls logs from various sources (just GCP for now), normalizes these raw events into a defined common schema, and delivers them to Splunk utilizing an least-once reliability design.


## **Status**

Working end-to-end: GCP → Splunk. Tested. See Known Limitations for scoped tradeoffs.


##**Overview**

SOCs need clean, normalized log data from various sources all flowing into one systemized dashboard (the SIEM). Raw logs arrive in various shapes (GCP stores them as LogObject), and a detection engineer needs a universal schema in order to write logic that queries all log sources.

This project implements an ingestion pipeline that pulls logs from GCP Audit Logs, normalizes them into a single event schema, and them ships these events to Splunk via HEC (HTTP Event Collector). The pipeline is structured for flexibility: adding a new source or new destination is an addition and not a modification.

I've decided to build this system in order to get a better understanding of data pipelines in a domain that is in my field of study (cybersecurity). I have experience utilizing various SIEMs for IR as well as tailoring detections, however I have not been able to see what the infrastructure enabling the SIEM looks like. This project accounted for that gap.


##**Architecture**
<img width="1735" height="1017" alt="image (1)" src="https://github.com/user-attachments/assets/3f5898a8-35f7-46f9-b5cb-bacd925f258b" />

This pipeline is built around a common Event schema. Every source format converges into this one schema and every destination format is built from it.

GCP Audit Logs  

      │  
      ▼  
      
  GCPSource         pull raw events (batch, checkpoint-resumable)  
  
      │  raw dicts  
      ▼  
      
  GCPNormalizer     raw dict  ->  validated common Event  
  
      │  Event  
      ▼  
      
  Pipeline          orchestrates; owns checkpointing, retry, dead-lettering  
  
      │  Event  
      ▼  
      
  SplunkFormatter   Event  ->  destination-shaped payload (HEC envelope)  
  
      │  HEC payload  
      ▼  
      
  SplunkSink        transport to SIEM; classifies failures  
  
      │  
      ▼  
      
    Splunk (HEC)

Sources and Normalizer interfaces are per-source. A Source pulls raw events from one system and a Normalizer maps that system's format into the common schema (Event).

Formatters and Sinks are per-destination. A Formatter reshapes an Event into one destination's expected structure while the Sink transports it to its specified destination.


##**Reliability Model**

This pipeline is based off of "at-least-once delivery." The source checkpoint is inclusive (timestamp >=), so a boundary event is never missed. However, the cost is that a boundary event may be re-pulled. Every event carries a deterministic event_id ({source}:{stable_id_or_hash}), so duplicates are identifiable and can be deduplicated downstream. It's favored to take redelivery over data-loss in the context of a data pipeline for a SIEM as lost logs can mean lost observability.

Unique Event IDs. When design this pipeline, flexibility and expansion were heavily weighted factors during blueprinting. With the pipeline ingetsing data from various sources, two edge cases arose. The first being the possibility of event ID collision across two (or more) different data sources (e.g. GCP generates id = 73632, Okta generates id = 73632). In order to prevent this case from happening, during normalization all extracted event IDs are prefixed with the source they originated from (e.g. GCP: gcp_audit-1782, Okta: okta-1782). The second edge case introduced was the possibility for no event_id to be returned from a data source (highly unlikely). To account for this case, any raw event in which an ID cannot be extracted, we create one while prefixing with its associated data source. ID creation is done through hashing in which we hash the entire raw event using a deterministic hash (sha256) to ensure that, same event = same ID. This hash is then prefixed by it's data source.

Checkpoint persistence. After a batch is successfully delivered to the sink, the source's next checkpoint is written to a per-source JSON file (will overwrite, only the newest confirmed checkpoint is needed). On a restart, the pipeline resumes from this checkpoint. Given that the checkpoint is written only after successful delivery, a crash mid-batch results in re-delivery, never silent loss. Again, this is to ensure data-loss is not possible.

Retry with exponential backoff + jitter. Transient sink failures are retried (within range of max_retries) with exponential backoffs to increase delays while adding a random jitter (this is to avoid hammering our Splunk endpoint if multiple processes are running at the exact same time).

The Sink classifies a failure (inspecting, e.g., HTTP status) and raises a specific exception. These exceptions are either: TransientSinkError or PermanentSinkError. The pipeline's retry wrapper reacts to the exception type and decides what to do. 

Transient Errors (429, 5xx, timeouts, etc.) are iteratively retried per the max allocated retries. If the retries exceed the max allocated retries, the pipeline halts. The assumption is that if the pipeline cannot reach Splunk after N retries (while exponentially backing off), we must assume that there is an issue on the Splunk endpoint that requires human intervention to resolve.

Permanent Errors (4xx) are written to a dead letter file (these are poisoned batches) where the batch information along with the error returned are appended. The pipeline will continue to the next iteration if a permanent error is returned. A permanent error shouldn't occur due to normalization and formatting, however it is a possible edge case that this design can handle if it were to ever appear.

Collapsing these two errors would result in integrity and availability concerns: dead-lettering everything during an outage results in data loss, and halting on one bad record loses availability. Segregating them lets the pipeline isolate poisoned batches while processing healthy ones, and halt+resume cleanly when the destination itself is unavailable.

Dead-letter file. Failed events (normalization failures and poisoned batches) are appended to a JSON-lines dead letter file, with each entry capturing the raw data, the error, the stage, and a timestamp. These entries are appended, not overwritten. This allows for the ability to triage our pipeline's history.


##**Project Structure**

.  

├── schema.py            # Abstract interfaces (Source, Normalizer, Formatter, Sink) and common Event schema  

├── gcp_src.py           # GCPSource: pulls GCP audit logs, GCPNormalizer: GCP raw -> Event  

├── pipeline.py          # Pipeline orchestrator, checkpoint/dead-letter/retry helpers, FileSink, SplunkFormatter, SplunkSink  

├── tests/               # unit tests (source, normalizer, formatter, pipeline, retry)  

├── pyproject.toml       # Poetry project + dependencies  

└── README.md


##**Setup**

###Prerequisites


Python 3.10+ (uses modern type-union syntax)
Poetry


Install

bashpoetry install

GCP credentials

Create a service account with the Logs Viewer (roles/logging.viewer) role, read-only. Download its JSON key, store it under a gitignored secrets/ directory, and point the standard env var at it:

bash# .env  (gitignored)
GOOGLE_APPLICATION_CREDENTIALS=/absolute/path/to/secrets/your-key.json

The pipeline loads this via python-dotenv. Secrets and runtime artifacts (secrets/, .env, output/, checkpoints/, dlq/) are gitignored and never committed.

Splunk (HEC)

<!-- [FILL] once built: HEC endpoint + token configuration, e.g. SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN env vars -->
Configure an HTTP Event Collector token in Splunk and provide the endpoint + token to the SplunkSink. <!-- [FILL] exact env var names / how you pass them -->


**Usage**

<!-- [FILL] Verify the entry point and flags against your actual code. -->
bashpoetry run python pipeline.py


once=True — pull only the available events and exit (useful for testing).
continuous mode — poll on an interval, tailing new events.
limit — max events pulled per batch.


Example normalized event

json{  

  "event_id": "gcp_audit-<id>",  
  
  "event_time": "2026-06-28T01:38:46Z",  
  
  "ingest_time": "2026-06-28T01:41:32Z",  
  
  "source": "gcp_audit",  
  
  "action": "google.iam.admin.v1.CreateServiceAccount", # modeled on UDM structure (read future work)  
  
  "outcome": "success",                                 # modeled on UDM structure (read future work)  
  
  "actor": {"type": "user", "id": "user@example.com"},  # modeled on UDM structure (read future work)  
  
  "target": {"id": "projects/example-project"},         # modeled on UDM structure (read future work)  
  
  "raw": { "<id>": "original event preserved verbatim" }  
  
}


**Testing**

bashpoetry run python -m pytest

Tests use dependency injection and fakes — no live API calls, so the suite runs anywhere. Coverage includes:


Source — batch pull, checkpoint advancement, filter construction (injected fake client).  

Normalizer — field mapping, actor-type detection, outcome results, malformed events routed to failures.  

Formatter — HEC envelope shape and epoch-time conversion.  

Pipeline — end-to-end flow (source → normalize → sink) with fakes; unique-event delivery under at-least-once.  

Retry — recovery from transient failures, and halt after retry exhaustion (time.sleep patched).



##**Known Limitations & Future Work**

These are deliberate, understood tradeoffs given the project scope. Each limitation is addressed with a known fix.


Composite checkpoint. The inclusive timestamp >= checkpoint re-pulls boundary events. A composite (timestamp, insertId) checkpoint would resume strictly after the last event, eliminating re-pulls while still never missing events. This limitation has been addressed with a "band-aid" fix for the time being as it interrupted with pipeline functionality in specific cases. See gcp_src.py and pipeline.py docstrings for more information.

Source-side retry. Retry/backoff currently wraps the sink. A transient failure on the source pull (e.g. a GCP read-quota 429) is not yet retried and will halt the pipeline. Extending the same backoff logic to the source pull closes this gap. This limitation is rare, GCP caps read requests at 60/min so rapid drain loops during testing can exceed this. In production, polling intervals and batch sizes keep request rates well under the limit, but the source pull should still be wrapped in the same retry/backoff logic as the sink.

Alerting & supervised restart. On transient-exhaustion the pipeline halts; it should emit structured CRITICAL logging and fire an alert (possible webhook notification to Slack/Teams). A pipeline restart is assumed to be handled by a supervisor (systemd/Kubernetes), which resumes from the un-advanced checkpoint.

Partial-batch failure. The sink contract is all-or-nothing per batch (appropriate for Splunk HEC which accepts or rejects at the batch level). A destination with per-item failure reporting (Elastic _bulk) would need a WriteResult return type to retry only the failed subset.

Null Description. Each normalized event contains a description field, as of now this field is = None. In order to fill this field with useful information, an LLM will interpret each normalized Event, and insert a natural language summary into the description field along with a triage hint for possible SOC investigation.


##**Roadmap**


Additional sources (Okta system logs, CrowdStrike, AWS CloudTrail).
UDM formatter targeting Google SecOps.
CI pipeline (lint, formatting, testing).



