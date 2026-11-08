const ID_PATTERN = /^hellolynk:(intl|cn):[a-z0-9][a-z0-9._-]{2,179}$/;
const CONFIRMATION_URL = /^https:\/\/hellolynk\.com\/account\?deviceRequest=devreq_[a-f0-9]{48}$/;
function acceptedInstanceName(value) {
  // Keep exact saved-intent names available for continuation. Only the enrollment
  // coordinator knows whether to apply the stricter new-name rule.
  if ([...value].length > 80
    || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(value)) return null;
  return value;
}

export function createWorkbenchConnectionForm(options) {
  const t = options.translate ?? ((key) => key);
  let connectionForm = null;
  const startConnection = function startConnection() {
    if (connectionForm) { connectionForm.querySelector("input")?.focus(); return; }
    const returnFocus = document.getElementById("connection-start") || document.activeElement;
    const form = document.createElement("div");
    form.className = "connection-fields";
    form.setAttribute("role", "form");
    form.innerHTML = `<a data-account href="https://hellolynk.com/account" target="_blank" rel="noopener noreferrer"></a>
      <label class="form-field"><span data-id-label class="form-label"></span><input data-id class="form-input" type="text" autocomplete="off" spellcheck="false" placeholder="hellolynk:intl:your-id" maxlength="195"></label>
      <label class="form-field"><span data-name-label class="form-label"></span><input data-name class="form-input" type="text" autocomplete="off" maxlength="80"><small data-name-help></small></label>
      <strong data-confirm-title class="connection-confirmation-title" hidden></strong>
      <p data-status class="connection-help" role="status" aria-live="polite"></p>
      <a data-confirm class="primary-button connection-confirm-button" target="_blank" rel="noopener noreferrer" hidden></a>
      <p data-confirm-help class="connection-help" hidden></p>
      <button data-submit type="button" class="primary-button"></button>
      <button data-cancel type="button" class="secondary-button"></button>`;
    const field = (name) => form.querySelector(`[data-${name}]`);
    const id = field("id"), name = field("name"), status = field("status"), submit = field("submit"), confirmation = field("confirm");
    let running = false;
    let waiting = false;
    let confirmInput = null;
    let statusKey = null;
    let statusCode = null;
    let idValidationKey = null;
    let nameValidationKey = null;
    const message = (key) => key ? t(`connectionForm.message.${key}`) : "";
    function render() {
      field("id-label").textContent = t("connectionForm.idLabel");
      field("account").textContent = t("connectionForm.account");
      field("name-label").textContent = t("connectionForm.nameLabel");
      field("name-help").textContent = t("connectionForm.nameHelp");
      name.placeholder = t("connectionForm.namePlaceholder");
      field("confirm-title").hidden = !waiting;
      field("confirm-title").textContent = t("connectionForm.confirmTitle");
      field("confirm-help").hidden = !waiting;
      field("confirm-help").textContent = t("connectionForm.confirmHelp");
      confirmation.textContent = t("connectionForm.step1");
      submit.className = waiting ? "secondary-button" : "primary-button";
      submit.textContent = running ? t("connectionForm.connectingButton") : waiting ? t("connectionForm.step2") : t("connectionForm.connect");
      field("cancel").textContent = t("action.cancel");
      status.textContent = message(statusKey)
        + (statusCode ? `\n${t("connectionForm.errorCode")}${statusCode}` : "");
      // A failed attempt must look like one; "connecting" and "confirm first" stay neutral.
      status.className = statusCode ? "connection-help is-error" : "connection-help";
      id.setCustomValidity(message(idValidationKey));
      name.setCustomValidity(message(nameValidationKey));
    }
    const observer = new MutationObserver(render);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["lang"] });
    function close() {
      observer.disconnect();
      form.remove();
      if (connectionForm === form) connectionForm = null;
    }
    startConnection.close = close;
    function invalidateConfirmation() {
      idValidationKey = null; nameValidationKey = null;
      id.setCustomValidity("");
      name.setCustomValidity("");
      if (waiting) {
        waiting = false; confirmInput = null; confirmation.hidden = true; confirmation.removeAttribute("href"); statusKey = null; statusCode = null; render();
      }
    }
    async function connect() {
      if (running) return;
      const instanceName = acceptedInstanceName(name.value);
      const input = { hellolynkId: id.value.trim(), instanceName: instanceName ?? name.value };
      idValidationKey = ID_PATTERN.test(input.hellolynkId) ? null : "idRequired";
      nameValidationKey = instanceName !== null ? null : "nameInvalid";
      render();
      if (!id.reportValidity()) return;
      if (!name.reportValidity()) return;
      if (confirmInput && JSON.stringify(confirmInput) !== JSON.stringify(input)) invalidateConfirmation();
      running = true; id.disabled = true; name.disabled = true; submit.disabled = true; field("cancel").disabled = true;
      statusKey = "connecting"; statusCode = null;
      render();
      try {
        const result = await options.connect(input);
        if (result.status === "confirmation_required" && CONFIRMATION_URL.test(result.verificationUrl)) {
          waiting = true; confirmInput = input;
          confirmation.href = result.verificationUrl; confirmation.hidden = false;
          statusKey = "confirmationRequired"; statusCode = null;
        } else if (result.status === "registered") {
          close();
          await options.onConnected(result);
        } else throw new Error("workbench_connect_result_invalid");
      } catch (error) {
        const value = String(error?.code || error?.message || "workbench_connect_failed");
        const safe = /^[a-z][a-z0-9_]{1,127}$/.test(value) ? value : "workbench_connect_failed";
        statusKey = safe === "network_certificate_untrusted" ? "networkCertificate"
          : ["network_name_resolution_failed", "network_connection_refused"].includes(safe) ? "networkAddress"
          : ["network_proxy_runtime_unsupported", "network_proxy_configuration_invalid", "network_system_proxy_unavailable"].includes(safe) ? "networkProxy"
          : ["device_enrollment_name_invalid", "agent_instance_name_invalid"].includes(safe) ? "enrollmentNameInvalid"
          : safe === "agent_instance_name_conflict" ? "nameTaken"
          : safe === "workbench_connect_name_invalid" ? "nameInvalid"
            : ["workbench_connect_id_invalid", "device_enrollment_hellolynk_id_invalid"].includes(safe) ? "idInvalid"
              : ["workbench_connect_busy", "device_enrollment_busy"].includes(safe) ? "busy"
                // powershell7_missing is certain. credential_helper_unavailable is thrown for any helper start failure
                // (most likely no PowerShell 7), so it gets a "may not be installed" message. Retrying cannot help either,
                // so neither may fall into the generic "unavailable" bucket below.
                : safe === "powershell7_missing" ? "powershell7Missing"
                  : safe === "credential_helper_unavailable" ? "credentialHelperUnavailable"
                    : safe === "device_enrollment_existing_profile_requires_setup" ? "existingSetup"
                      : safe === "device_enrollment_intent_conflict" ? "savedConnectionConflict"
                        : safe === "device_enrollment_authorization_expired" ? "authorizationExpired"
                          : /timeout|request_failed|unavailable/.test(safe) ? "resultPending"
                            : /conflict|existing_profile|owner_mismatch/.test(safe) ? "existingConnection"
                              : "failed";
        statusCode = safe;
        if (["device_enrollment_name_invalid", "workbench_connect_name_invalid", "agent_instance_name_invalid", "agent_instance_name_conflict"].includes(safe)) nameValidationKey = statusKey;
      } finally {
        running = false; id.disabled = false; name.disabled = false; submit.disabled = false; field("cancel").disabled = false; render();
      }
    }
    submit.addEventListener("click", () => { void connect(); });
    field("cancel").addEventListener("click", () => {
      close();
      if (returnFocus?.isConnected && !returnFocus.hidden && !returnFocus.disabled
        && !returnFocus.closest('[hidden], [inert], [aria-hidden="true"]')) {
        returnFocus.focus({ preventScroll: true });
      }
    });
    for (const input of [id, name]) {
      input.addEventListener("input", invalidateConfirmation);
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && !event.isComposing) { event.preventDefault(); void connect(); }
      });
    }
    for (const link of [field("account"), confirmation]) {
      if (typeof options.openLink === "function") link.addEventListener("click", (event) => {
        event.preventDefault();
        void Promise.resolve().then(() => options.openLink(link.href)).catch(() => {
          statusKey = "websiteOpenFailed"; statusCode = null; render();
        });
      });
    }
    render();
    document.getElementById("connection-guide").append(form);
    connectionForm = form;
    id.focus();
  };
  return startConnection;
}
