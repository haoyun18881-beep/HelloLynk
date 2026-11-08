// Human unread is preserved unless the human explicitly enabled the separate
// local conversation preference. Never accept an unexplained false read flag.
export function projectInboxReadState(value) {
  if (value?.readDoesNotMarkRead === true && value.humanReadAutomatically === undefined) {
    return { readDoesNotMarkRead: true };
  }
  if (value?.readDoesNotMarkRead === false && value.humanReadAutomatically === true && value.unread === false) {
    return { readDoesNotMarkRead: false, humanReadAutomatically: true };
  }
  return null;
}
