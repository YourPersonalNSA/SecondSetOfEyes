
Below is the accompanying browser script that listens for tab events and forwards them via a fetch request to http://localhost:8088/intercept_url

```js
//
// We can't be bothered to sign a browser extension so are living off the land:
// https://addons.mozilla.org/en-US/firefox/addon/webrequest-rules
//
// This legitimately great extension not only offers an easy way of
// tinkering with WebRequest API, is also allows us to run whatever
// in the background script, including looking at tab events
//
// USAGE:
// - Install WebRequest Rules extension
// - Enable notifications permission in settings
// - Add a new rule
// - Put this into Match Request handler
//
let prefix = "http://localhost:8088/"

if (details.url.startsWith(prefix)) {
    return false
}

// https://stackoverflow.com/questions/17415579/how-to-iso-8601-format-a-date-with-timezone-offset-in-javascript
function toIsoString(date) {
  var tzo = -date.getTimezoneOffset(),
      dif = tzo >= 0 ? '+' : '-',
      pad = function(num) {
          return (num < 10 ? '0' : '') + num;
      };

  return date.getFullYear() +
      '-' + pad(date.getMonth() + 1) +
      '-' + pad(date.getDate()) +
      'T' + pad(date.getHours()) +
      ':' + pad(date.getMinutes()) +
      ':' + pad(date.getSeconds()) +
      dif + pad(Math.floor(Math.abs(tzo) / 60)) +
      ':' + pad(Math.abs(tzo) % 60);
}

// Reset when extension is disabled/reenabled
if (browser["persistf"] == undefined) {
    fetch(prefix + "setup")
    browser["persistf"] = function(id, change, tab) {
        function success_cb() {
        }

        function failure_cb() {
            browser.notifications.create("intercept-alert", {
                type: "basic",
                title: "InterceptURLs",
                message: "Unable to push data",
            })
        }

        if (change.status == "complete" || (tab.status == "complete" && change.title != undefined)) {
            fetch(prefix + "intercept_url", {
                method: "POST",
                body: JSON.stringify({
                    time: toIsoString(new Date()),
                    title: tab.title,
                    url: tab.url
                })
            }).then(success_cb, failure_cb)
        }
    }
    browser.tabs.onUpdated.addListener(browser["persistf"] )
}

return true
```
