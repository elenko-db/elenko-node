1\. Flow documents (multi-step pipelines)

Doc type: elenko\_flow in the config DB.

Fields: name, description, steps (array of { target, param, label }).

Step targets: Same as today: Log (passthrough), Call API, Send to Local DB.

CRUD: List at /flows, create at /flows/create, edit at /flows/:id/edit. Start page has a Flows link next to Entry forms and APIs.



2\. Flow editor

Steps table: #, Target (Log / Call API / Send to Local DB), Label, Param (API doc id or profile id).

Add/remove steps, then Save. Steps run in order; data flows from one step to the next.



3\. Pipeline behaviour

Log: Sends current payload to the flow log and passes it unchanged to the next step.

Call API: Calls the API (param = API doc id), then passes the response (and optional responseField update) to the next step. If the API doc has responseTarget: "update", the source entry is updated with the response so the UI shows it.

Send to Local DB: Creates an entry in the target profile (param = profile id) from the current dataset; next step receives the same dataset plus \_lastCreatedId.



4\. Form configuration

In Entry form edit, each flow button row has a Flow (optional) column.

Dropdown: “Single step” (current behaviour) or a Flow document (by name).

If a Flow is chosen, that button runs the full pipeline; Target/Param on the row are ignored for execution (they stay for display/backward compatibility).

flowId is stored on each flowConfig and used when the user clicks the button.



5\. Technical details

createEntryInProfileFromContext is shared between the flow worker and the pipeline and returns the created doc.

runApiCallAndWait runs one API call and resolves with the response (used in the pipeline); the API worker supports an optional requestId for this.

runPipeline(context, flowDoc) runs the steps in order and mutates context (e.g. dataset, lastApiResponse, \_lastCreatedId).

You can now define flows like “Log → Call API (e.g. Mistral) → Send to Local DB” and attach them to an entry form; clicking the button runs the whole chain with data passed between steps.

