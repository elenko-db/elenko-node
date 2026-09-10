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









Summary of what was wrong and what was changed:



Cause



Create button / script failure

The template used const initialSteps = ${stepsJson}; but the variable was renamed to stepsJsonSafe and never passed into the script. So stepsJson was undefined at render time. Depending on how the template was evaluated, the page could throw when rendering or produce invalid script (const initialSteps = undefined;), which could break the rest of the script.



Add step button

If the script failed early (e.g. due to stepsJson), the rest never ran, so addBtn.onclick was never set. In addition, the Remove button used an arrow function that didn’t call updateStepNums() after removing a row.



Fixes



Safe steps data



Added a JSON data block: <script type="application/json" id="initial-steps-json">${stepsJsonSafe}</script> so steps are not inlined into executable script (avoids </script> in step labels breaking the page).

In the main script, initial steps are read from that element with JSON.parse(document.getElementById('initial-steps-json').textContent) and a fallback to \[{ target: 'log', param: '', label: 'Log' }] if the element is missing or parsing fails.

Add step



Null check in addStepRow: if (!tbody) return; so it doesn’t throw if the tbody isn’t found.

Add step handler set with a normal function: addBtn.onclick = function() { addStepRow(...); }; so it’s always attached when addBtn exists.

Form submit



Submit is bound only when the form exists: if (formEl) formEl.onsubmit = async (e) => { ... }.

Steps are built only when tbody exists: (tbody ? Array.from(tbody.querySelectorAll('.flow-step-row')) : \[]).map(...) so submit doesn’t throw when tbody is null.

Remove step



Remove button now calls updateStepNums() after removing a row so the step numbers stay correct.

With these changes, the Flow create page should render without script errors, “+ Add step” should add rows, and “Create” should POST to /api/flows and create the document. If something still fails, open the browser dev tools (F12 → Console) and check for errors when loading the page, when clicking “+ Add step”, and when clicking “Create”




# Sandbox Execution

1. VM sandbox (already in place)

runScriptInSandbox(script, input, timeoutMs) uses Node vm.runInContext with a minimal context: only input (read-only copy of pipeline data) and output (object to write to; merged back into context.dataset). No require, process, file, or DB access.
Timeout is configurable per JS Processing doc (100–60000 ms, default 5000).
2. Transfer in/out

Data in: input = shallow copy of current context.dataset.
Data out: script writes to output; after success, result.output is shallow-merged into context.dataset.
3. Return value → logging only

Script return value is not used for data. It’s sent in flow.scriptReturn (with returnValue, error, stepIndex, param, profileId, entryId). The flow worker logs all non-routed messages, so return value and errors go to the flow log.
4. Trusted-admin / hash protection

JS Processing docs are admin-only (create/update via requireAdmin).
On create/update the server sets doc.hash = computeScriptHash(doc.script).
When a flow runs a script step (for any user), the server checks:
If the script is non-empty but has no hash → error: “Script has no integrity hash. Save the JS Processing document as admin first.”
If hash is present and differs from computeScriptHash(script) → error: “Script integrity check failed (hash mismatch). Only an admin can update the script.”
So non-admins can run flows that use the step, but only the admin-defined script (and its hash) is executed.
5. JS Processing CRUD and UI

Config document: type: "elenko_js_processing" with name, description, script, timeout, hash (set on save).
Routes: GET/POST /api/js-processing, GET/PUT /api/js-processing/:id, GET /js-processing, /js-processing/create, /js-processing/:id/edit (all create/edit require admin).
Pages: List table (name, id, description, timeout, Edit) and edit form (name, description, timeout, script textarea).
Start page: “JS Processing” link added next to Flows and APIs.
6. Flow edit UI

Step target dropdown includes “Run script (JS Processing)” (target: "script").
Param field placeholder: “JS Processing doc id or name”; placeholder updates when the target is changed.
7. Config DB

Lookup by id uses configDb.get(param); by name uses configDb.find({ selector: { type: "elenko_js_processing", name: param } }). Existing apis-by-type-name index on ["type","name"] is used for the by-name query.
8. Flow log

flow.scriptReturn and flow.scriptError are sent via sendFlowMessage. The flow worker logs every message that isn’t routed to localDb/api, so both are written to the flow log.
Sandbox stays minimal (no file or DB access in this version); extensions can be added later via the JS Processing config or pipeline context as needed.


