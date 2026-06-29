from abc import ABC, abstractmethod 
from dataclasses import dataclass
from typing import Any
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, ConfigDict, field_validator

class LogSource(str, Enum):
    """
    this class is for defining all the possibly log sources this
    ingestion pipeline contains (or will contain), at the time of this comment
    gcp is the only supported log source
    """
    GCP_AUDIT = "gcp_audit"
    OKTA_SYSTEM_LOG = "okta_system_log"
    CROWDSTRIKE = "crowdstrike"
    AWS_CLOUDTRAIL = "aws_cloudtrail"

class ActorType(str, Enum):
    """
    this class is for defining the types of actors to be placeed into the actor class,
    the purpose of this implementation was to model UDM formatting, given that Google
    SecOps doesn't offer a free trial, the next best option was to model their format.
    """
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    SYSTEM = "system"
    UNKNOWN = "unknown"

class Outcome(str, Enum):
    """
    same thing as the class above, this is a UDM field. purpose for modeling UDM formatting
    """
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    CHALLENGE = "challenge"
    UNKNOWN = "unknown"

class Actor(BaseModel):
    """
    pydantic model dataclass, built for validation,
    enforce types at creation time and will
    raise an error if data is not of the specified type,
    basically, we should always validate external data (okta, gcp)
    immediately rather than accepting it with the possibility
    of it crashing the program.

    same thing as the class above, this is a UDM field. purpose for modeling UDM formatting
    """
    type: ActorType
    id: str | None = None      # could be an email, service-account id, SID, etc. whatever the source's stable identifier is
    display_name: str | None = None

class Target(BaseModel):
    """
    pydantic model dataclass, built for validation,
    enforce types at creation time and will
    raise an error if data is not of the specified type,
    basically, we should always validate external data (okta, gcp)
    immediately rather than accepting it with the possibility
    of it nuking the program pipeline in a later function.
    -----
    same thing as the class above, this is a UDM field. purpose for modeling UDM formatting
    """
    type: str | None = None      # string or nothing, with initial value set to none
    id: str | None = None
    display_name: str | None = None

class Event(BaseModel):
    """
    pydantic model dataclass, built for validation,
    enforce types at creation time and will
    raise an error if data is not of the specified type,
    basically, we should always validate external data (okta, gcp)
    immediately rather than accepting it with the possibility
    of it nuking the program pipeline in a later function.

    this is our event class, event is our core scehma for data normalization.
    every raw log event from various sources eventually gets normalized to 
    this exact schema. an important note about my chosen schema is that
    for every event_id, i have decided to append a prefix to it. the reason is due to the fact that 
    varying log sources have an edge case in which they COULD produce the same id, very unlikely
    but we must take that possibility into account. with this being the case every raw event id
    that is mapped to my schema is prefixed by the log source in each it comes from:
    e.g. gcp_audit-624628, okta-15355. another note about event_id, again in the highly unlikely but
    possible edge case a raw event DOES NOT have an id that can be mapped to my schema, we generate
    a deterministic hash for said event and prefix it with its source. this ensures that ALL events have an id
    no matter what.
    """
    event_id: str                # f"{source}:{stable_id_or_hash}"
    event_time: datetime         # UTC from the data source
    ingest_time: datetime        # UTC from the pipeline
    source: LogSource            
    action: str                  
    outcome: Outcome = Outcome.UNKNOWN
    actor: Actor | None = None
    target: Target | None = None
    description: str | None = None
    raw: dict                    # the og event

    model_config = ConfigDict(extra="forbid") # pydantic controls, will make pydantic raise an error if an Event is constructed with a field name not defined above

    @field_validator("event_time") #ensures the method below only validates event_time field in core schema
    @classmethod 
    def utc_set(cls, value: datetime)-> datetime: 
        """
        this function serves the purpose of validating event_time (the normalized raw timestamp) as UTC in the case of 
        1. naive timestamps, if naive are present we raise, we should not be getting any naive however must cover all edge cases
        2. non UTC aware - these are just timestamps not following proper format, can and will be re-formatted to match UTC
        """
        if value.utcoffset() is None:
            raise ValueError("Naive timestamps (no-timezone) are rejected. event_time must be timezone-aware.")
        return value.astimezone(timezone.utc)

@dataclass
class BatchResults: 
    """
    holds the results of the raw batch pulled from batch_pull
    it includes the pulled events as a list, to be indexed
    and pulls the next_checkpoint for the purpose of continuing from 
    where the batch_pull method left off on its last call.
    """
    events: list[dict]
    next_checkpoint: Any | None # any or none as next_checkpoint is optionally absent, bc checkpoint can be anything depending on the data source

class Source(ABC):
    """
    source emits raw events in their own native 
    shapes (Okta JSON, GCP audit LogObjects, CrowdStrike Events, etc)
    these shapes are then to be thrown into the normalizer.
    """
    @abstractmethod
    def batch_pull(self, limit: int = 100, checkpoint: Any | None = None) -> BatchResults: # come back to the limit decision for fine-tuning, source's may have diff limit sizes
        """
        pull all the raw events up to the defined limit, starting from the defined checkpoint (none)
        when checkpoint is none, that means we are starting from the beginning
        then the function would return the pulled raw events along with the checkpoint
        so on the next call, the function picks up where the last checkpoint left off
        this will return a class that contains events and the next checkpoint
        """
        ... 

@dataclass
class FailedEvent:
    """
    data class to hold events that were deemed malformed by the normalizer, will contain the raw event
    along with the error associated with the malformation
    """
    raw: dict
    error: str

@dataclass
class NormalizeResults():
    """
    holds the results for events that were successfully normalized
    as well as failures (due to malformed logs)
    failures returns the raw along with an error message for help with troubleshooting
    """
    events: list[Event]
    failures: list[FailedEvent]

class Normalizer(ABC):
    """
    per source translator that takes the raw event from Source and produces a single Event. 
    event our schema (Pydantic model), as stated earlier
    everything after normalization speaks only in Events, raw isn't touched again 
    unless you want to be technical about it, it's included in the raw field in Event
    """
    @property
    @abstractmethod
    def source(self) -> LogSource:
        """
        same enforcement as the abstractmethod, basically ensuring that every Normalizer interface 
        created conatains this attribute, accessed like data rather than invoked like a function
        every normalizer made MUST provide a source, a stable attribute that never changes
        """
        ...

    @abstractmethod
    def extract_stable_id(self, raw_event: dict) -> str | None:
        """
        this will return the sourced event's stable id (whatever its native log ID was)
        and if there is no stable id with said log, it will return none
        if this edge case appears, it gets handled by the make_event_id function via hash
        """
        ...

    def make_event_id(self, raw_event: dict) -> str:
        """
        this will prefix the extracted stable id from the previous function 
        with the source to which it came from (okta, gcp, aws, etc)
        and if no stable id exists (edge case) the raw event will get hashed (deterministic hashinh via hashlib sha256)
        in order to maintain uniqueness (acts as it's ID), given that every log
        has an ID (whether extracted or hashed), always expect a string to return
        """
        ...

    @abstractmethod
    def normalize_batch(self, raw_events: list[dict], ingest_time: datetime) -> NormalizeResults:
        """
        this will take the batch of raw events, normalize AND organize them
        depending on whether or not they were successfully normalized events (mapped to core schema)
        or failures (malformed logs)
        """
        ...
    
class Formatter(ABC):
    """
    formatter takes the normalized Event (class) and produces the destination's shape aka:
    splunkformatter wraps the Event in the HEC envelope (so it can actually be pushed to splunk)
    and a udmformatter that maps core schema (Event) to their UDM counterparts
    purpose of the UDM formatter is to match the use case of Google SecOps SIEM 
    will have two implementation/interfaces - UDM Formatter and Splunk Formatter
    """
    @abstractmethod
    def format(self, event: Event) -> dict:
        """
        simple method that takes a normalized event and formats it
        per the caller's purpose (HEC vs. UDM)
        """
        ...

class TransientSinkError(Exception):
    """
    signals error classification when a specific HTTP response error is returned 
    members include 429, 502, 504 + timeouts
    when this error occurs, retry + exponential backoff with jitter is done for all retries in max_retries
    """ 

class PermanentSinkError(Exception):
    """
    signals classification when a specific HTTP response error is returned 
    members include most 4xx
    when this error occurs, we dead-letter the batch 
    indicates the following possibilities: field exceeded allocated size in SIEM (usually raw)
    possible auth/perm failure, or core schema mismatches splunk's accepted schema
    if permanentsinkerror is raised, there is nothing that can be done on the pipeline's end
    """

class Sink(ABC):
    """
    takes the formatted records and send them upstairs (to splunk) via HTTP-POST-to-HEC (http event collector)
    sink also ships a file for the UDM JSON (for the Google SecOps use case)
    """
    @abstractmethod
    def write(self, records: list[dict]) -> None:
        """
        transient exception results in a retry + backoff
        permanenet exception results in a dead letter 
        no raise? -> a successful batch delivery
        """
        ...
