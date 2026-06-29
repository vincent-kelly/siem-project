from gcp_src import *
from pathlib import Path
import random
import time
from dotenv import load_dotenv; load_dotenv()

def write_checkpoint(file_path, checkpoint):
        """
        does exactly what it says, writes the checkpoint from batch_pull to
        the checkpoints file for hardcoding. this is because in the case that 
        the pipeline is in its Nth iteration and it crashes, endpoint goes down, etc
        the next_checkpooint is hardcoded to disc so it can pick up exactly where it
        left off instead of having to start all over again and pull batches that
        have already been processed.
        ---
        with that being said, write_checkpoint will only execute once the formatted batch
        has successfully been sent to splunk, as that is the sole indication that the batch
        has been fuly processed and we can move onto the next one
        """
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w") as f:
            f.write(json.dumps(checkpoint))

def checkpoint_read(file_path):
    """
    again, self explanatory. reads the checkpoint from the checkpoint file if there is one
    """
    if Path(file_path).exists():
        try:
            with open(file_path, "r") as f:
                checkpoint = json.load(f)
                return checkpoint
        except (json.JSONDecodeError, ValueError):
            return None
    return None 

def write_to_dead_letter(file_path, fails, errors, stage):
        """
        this function is designed to write all the failures recorded from the entire pipeline
        flow to a dedicated file. failures come from two places in the pipeline:
        malformed logs that cannot be normalized (the normalizer) or batches that cannot be 
        pushed into splunk (the sink) due to the endpoint being down, limiting, etc.
        """
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "a") as f:
            for fail in fails:
                entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "stage": stage,
                    "error": errors,
                    "data": fail,
                }
                f.write(json.dumps(entry) + "\n")

def write_with_retry(sink, records, dead_letter, max_retries=5):
    """
     write_with_retry - here is where we push our normalized and formatted events into splunk
     or our sink. in order to avoid trigger rate limits, we write with retries and expontential
     backoff (with a jitter). for every time we retry the wait increases, with the cap being 10 + jitter.
     the purpose of the jitter is solely in case we are running multiple writes at once from various sources
     (future plan) in order to avid any sort of errors caused by hammering the endpoint
    """
    for retry in range(max_retries):
        try:
            sink.write(records)
            return
        except TransientSinkError: # 5xx, 429, or timeouts. 
            if retry == max_retries -1:
                break
            wait = min(2 ** retry, 10) + random.uniform(0, 0.5)
            time.sleep(wait)
        except PermanentSinkError as e: # 4xx cause this
            write_to_dead_letter(dead_letter, records, str(e), "sink")
            return
    raise RuntimeError("Sink was never reached after all retry attempts - stopping")

class FileSink(Sink):
    """
    our file sink, this is leveraged for local testing or if one's use case requires
    events to be stored locally on disc. really the only reason this was made is due to
    the UDM use case as well as testing the pipeline wiring while waiting for Splunk access
    """
    def __init__(self, path: str):
        self.path = path
    
    def write(self, records: list[dict]) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a") as f: # auto open auto close
            for record in records:
                f.write(json.dumps(record) + "\n") 

class SplunkFormatter(Formatter):
    """
    this is the splunk formatter, takes our Event and formats it for Splunk HEC (HTTP Event Collector)
    """
    def format(self, event: Event) -> dict:
        epoch = event.event_time.timestamp()
        payload = event.model_dump(mode="json")
        return {
            "time": epoch,
            "sourcetype": "gcp-audit", # these hard codes will have to be changed later if i add more sources
            "source": "siem-ingest", # these hard codes will have to be changed later if i add more sources
            "event": payload,
        }

class Pipeline():
    def __init__(self, source, normalizer, sink, checkpoint_path, dead_path):
        self.source = source
        self.normalizer = normalizer
        self.sink = sink
        self.checkpoint_path = checkpoint_path
        self.dead_path = dead_path

    def run(self, limit = 100, poll_intervals = 5, once = False):
        """
        this is pipeline execution, step by ste, wiring all components of the pipeline into one
        keeping this method inside a class makes it easier to test functionality and make 
        edits in the future. still needs some optimization for possible rate limits, but
        shouldn't be too bad (a logic error occured resulting in this pipeline pulling > 60 different batches 
        in less than a minute, GCP rate limits > 60 calls per minute, ts highly unlikely that in a 
        production use case we would be making more than 60 calls a minute if are batch sizes are large.
        however its imperative to cover all edge cases so for future updates this will be taken care of.
        ---
        the band aid fix I spoke of earlier is preesent in this block (if batch.next_checkpoint == checkpoint),
        this also needs to be addressed as its really just extra code being used to fix an underlying problem.
        """
        checkpoint = checkpoint_read(self.checkpoint_path)

        while True:
             batch = self.source.batch_pull(limit = limit, checkpoint = checkpoint) # gonna have to add exponential backoff here, hit 429s on live tests

             if not batch.events:
                 if once:
                     return
                 time.sleep(poll_intervals)
                 continue
             
             if batch.next_checkpoint == checkpoint: # temporary fix, this needs to be revisited later. this correlates to the band aid fix I spoke of earlier.
                if once:
                    return
                time.sleep(poll_intervals)
                continue
             
             ingest_time = datetime.now(timezone.utc)

             results = self.normalizer.normalize_batch(batch.events, ingest_time)

             for fail in results.failures:
                 write_to_dead_letter(self.dead_path, [fail.raw], fail.error, "normalize")

             records = [e.model_dump(mode="json") for e in results.events]

             write_with_retry(self.sink, records, self.dead_path)

             write_checkpoint(self.checkpoint_path, batch.next_checkpoint)

             checkpoint = batch.next_checkpoint

source = GCPSource("siem-project-500620")
normalizer = GCPNormalizer()
sink = FileSink("output/events.jsonl")

pipeline = Pipeline(
    source=source,
    normalizer=normalizer,
    sink=sink,
    checkpoint_path="checkpoints/gcp_checkpoint.json",
    dead_path="dlq/gcp_dead.jsonl",
)

pipeline.run(limit=50, once=True)   # once=true so it drains and stops, not infinite runs
print("Pipeline run complete.")