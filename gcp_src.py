from schema import *
from typing import Any
from google.cloud import logging
from datetime import datetime, timezone
import requests
import hashlib
import json

class GCPSource(Source):
    """
    first source interface dedicated to GCP
    GCPSource inherits from Source ABC
    """
    def __init__(self, project_id: str, client = None):
        """
        init is defined as we are giving the opportunity for flexibility in gcp
        if one has multiple gcp projects they would like to ingest logs for,
        they would initialize multiple GCPSource interfaces and enter their project_id's
        according as the parameter.
        ----
        the client parameter should only be filled when testing, (see the self.client = client if ... line below),
        when the client parameter is left unfilled, the interface will default to the production
        project id that we have provided it with
        ----
        personal note, get into the habit of developing for flexibility 
        always assume that someone else will use your code with different
        configurations, keys, and tuning than you. this is open-source after all
        key word: portability
        """
        self.project_id = project_id
        self.client = client if client is not None else logging.Client(project = project_id) 
        self.base_filter = f"logName=\"projects/{self.project_id}/logs/cloudaudit.googleapis.com%2Factivity\""

    def batch_pull(self, limit: int = 100, checkpoint: str | None = None) -> BatchResults:
        """
        batch_pull - this method serves the purpose of... pulling batches!
        provide it a limit, and it will pull x amount of raw events.
        by default, checkpoint is none, this is means that this is our first run and we are 
        starting from the beginning (the oldest query found). by default GCP is on a 24 hour window
        so batch_pull oldest possible event would be 23hrs and 59mins from when its ran. if this is 
        ran in a production setting (on a constant loop), this should not cause any problems
        ----
        when a LogObject (GCPs name for a raw event) is pulled down, GCP hands them off in the style of a 
        Generator function, so the results must be thrown into a list(). from the list, the last raw event pulled 
        "results[-1]" timestamp will be used as the next_checkpoint for when batch_pull is called again, this ensures 
        that we always pick up from where we leave off.
        ----
        in query =, theres a specific issue that will be addressed in later updates as right now is being 
        fixed in a band aid approach :( , the issue is that "AND timestamp >=" was chosen as the clause to 
        ensure that no logs are lost(see last line explaining why), however when testing the entire pipeline it was found out that the >=
        has the possibility to pull duplicate entries do to the "or equal to" clause. by the time i noticed this
        the pipeline was nearly complete and it would mean having to break alot of existing functionality (note, >= could
        not simply be changed to > as that would mean possible loss of log if there were multiple logs that happened at the exact 
        same millisecond as the log timestamp that defined next_checkpoint), which is quite common in logging.
        """
        if checkpoint is None:
            query = self.base_filter
        else:
            query = self.base_filter + f" AND timestamp >= \"{checkpoint}\""
        results = list(self.client.list_entries(filter_ = query, order_by = logging.ASCENDING, max_results = limit)) # GCPs wrapper command for API call
        if results:
            next_checkpoint = results[-1].timestamp.isoformat() # this is our checkpoint builder, basically we take the last event from the list above (newest event), we pull the timestamp field from that event and format it to RFC3339 as without formatting it returns a non-acceptable string
        else:
            next_checkpoint = checkpoint
        raw_events = [result.to_api_repr() for result in results] # run to_api-repr on the current result for every result inside of results - convert every LogEntry object to JSON, list em
        return BatchResults(raw_events, next_checkpoint)
    
class GCPNormalizer(Normalizer):
    """
    this is the normalizer, we take our raw events from GCP and normalize them to our common schema.
    """
    @property 
    def source(self):
        return LogSource.GCP_AUDIT
    
    def extract_stable_id(self, raw_event: dict ) -> str | None: 
        """
        self explanatory, retrieves the id from a raw event (or not if it doesn't exist)
        """
        return raw_event.get("insertId")
        
    def make_event_id(self, raw_event: dict) -> str:
        """
        self explanatory, makes the custom event id as explained in the schema - includes
        the prefixing functionality as well as the hashing functionality if an id is non-existent.
        ----
        handy hash: if an ID doesn't exist on a GCP log (this would never happen, just edge case)
        we need an identifier that is unique while being deterministic. this means that the same raw event
        must always produce the same id for every run, forever and ever. with this being the case we need...
        a cryptographic hash. hashlib must be used here for multiple reasons 1. its deterministic,
        2. it gives stable hashes (sha256 here). in order for us to actually hash the entire raw event it 
        cannot be a dictionary (batch_pull.results returns a dictionary list) so we use json.dumps 
        to turn it into a json string  that is then sorted by keys. the sort is to ensure that the 
        same dictionary always seralizies identically regardless of the key order it arrives it. 
        and then finally that sorted json string is encoded into bytes for the hash input.
        ---
        (explained in schema) also, the reason why we slap a prefix on all these IDs is because we want to ensure that there is 
        no possibility for duplicates across differing data sources e.g. gcp_audit-<enter_id> vs okta-<enter_id>
        unlikely that this happens, however it is an edge case. better to leave no stone unturned
        """
        stable_id = self.extract_stable_id(raw_event)
        if stable_id is None:
            handy_hash = hashlib.sha256(json.dumps(raw_event, sort_keys=True).encode("utf-8")).hexdigest()
            return f"{self.source.value}-{handy_hash}"
        else:
            return f"{self.source.value}-{stable_id}" 

    def normalize_batch(self, raw_events: list[dict], ingest_time: datetime) -> NormalizeResults:
        """
        normalize_batch does exactly what it says, it normalizes the raw events into our common schema
        this function needs to be optimized in future commits, i'm thinking a helper function to handle
        all the conditional transformations that are inside of the event. also we will need to account for 
        the possibility error status codes being mapped to failure in the outcome field.
        ---
        mainly, the fields that need optimzation are the UDM fields. fun idea - for the description field 
        i was thinking of calling haiku to process the raw event and have it input a quick sentence or two 
        of what exactly this log is in natural language. as of now its just blank, again somthing that will be
        modified in a future commit.
        """
        success = []
        fail = []
        for raw in raw_events:
            try:
                auth_info = raw.get("protoPayload", {}).get("authorizationInfo", [])
                principal = raw.get("protoPayload", {}).get("authenticationInfo", {}).get("principalEmail")
                resource_id = raw.get("protoPayload", {}).get("resourceName")
                event = Event(
                    event_id = self.make_event_id(raw),             
                    event_time = raw.get("timestamp"),
                    ingest_time = ingest_time, 
                    source = self.source,      
                    action = raw["protoPayload"]["methodName"],
                    outcome = Outcome.DENIED if any(entry.get("granted") is False for entry in auth_info) else (Outcome.SUCCESS if auth_info else Outcome.UNKNOWN), # account for non-empty error status being mapped to FAILURE, will cover in future commit
                    actor = Actor(type = ActorType.SYSTEM if principal is None else (ActorType.SERVICE_ACCOUNT if principal.endswith("gserviceaccount.com") else ActorType.USER), id = principal, display_name = None),
                    target = Target(type = None, id = resource_id, display_name = None),
                    description = None, # nothing for now. Future update will include AI triage of log (claude haiku)
                    raw = raw,
                )          
                success.append(event)
            except Exception as e:
                fail.append(FailedEvent(raw=raw, error=str(e)))
        return NormalizeResults(events = success, failures = fail)