#!/bin/sh

MODNAME=newt
SETTINGS=/opt/$MODNAME/etc/settings
LOGFILE=/tmp/newt.log
PIDFILE=/tmp/newt.pid

# Escape special HTML characters
htmlesc() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g'
}

# Decode URL-encoded form values (handles common chars in endpoints/ids/secrets)
urldecode() {
    printf '%s' "$1" | sed \
        -e 's/+/ /g' \
        -e 's/%3[Aa]/:/g' -e 's/%3[aa]/:/g' \
        -e 's/%2[Ff]/\//g' -e 's/%2[ff]/\//g' \
        -e 's/%40/@/g' \
        -e 's/%2[Ee]/./g' \
        -e 's/%2[Dd]/-/g' \
        -e 's/%5[Ff]/_/g' \
        -e 's/%3[Dd]/=/g' \
        -e 's/%3[Ff]/?/g' \
        -e 's/%23/#/g' \
        -e 's/%25/%/g'
}

# Extract a named field from URL-encoded POST data (awk splits on & without tr)
get_field() {
    printf '%s' "$2" | awk -v f="${1}=" 'BEGIN{RS="&"} index($0,f)==1 {print substr($0,length(f)+1); exit}'
}

# Check whether newt process is alive
is_running() {
    [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null
}

ensure_settings_file() {
  [ -f "$SETTINGS" ] && return
  if [ -f "/opt/$MODNAME/etc/defaults" ]; then
    cp "/opt/$MODNAME/etc/defaults" "$SETTINGS" 2>/dev/null
  else
    printf 'MOD_PANGOLIN_SITE_ENABLED=0\n' > "$SETTINGS"
  fi
}

set_setting_raw() {
  key="$1"
  value="$2"
  ensure_settings_file
  awk -v k="$key" -v v="$value" '
    BEGIN { done=0 }
    index($0, k "=") == 1 { print k "=" v; done=1; next }
    { print }
    END { if (!done) print k "=" v }
  ' "$SETTINGS" > "$SETTINGS.tmp" && mv "$SETTINGS.tmp" "$SETTINGS"
}

quote_sh_value() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# ── Read POST body ──────────────────────────────────────────────────────────
POST_DATA=""
if [ "$REQUEST_METHOD" = "POST" ] && [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
    POST_DATA=$(dd bs="$CONTENT_LENGTH" count=1 2>/dev/null)
fi

# ── Load current settings ───────────────────────────────────────────────────
MOD_PANGOLIN_SITE_ENABLED=0
MOD_PANGOLIN_SITE_ENDPOINT=""
MOD_PANGOLIN_SITE_ID=""
MOD_PANGOLIN_SITE_SECRET=""
[ -f "$SETTINGS" ] && . "$SETTINGS"

# ── Handle actions ──────────────────────────────────────────────────────────
if [ -n "$POST_DATA" ]; then
    ACTION=$(get_field "action" "$POST_DATA")
    case "$ACTION" in
        save)
            EP=$(urldecode "$(get_field "endpoint" "$POST_DATA")")
            ID=$(urldecode "$(get_field "id"       "$POST_DATA")")
            SEC=$(urldecode "$(get_field "secret"  "$POST_DATA")")
        set_setting_raw "MOD_PANGOLIN_SITE_ENDPOINT" "\"$(quote_sh_value "$EP")\""
        set_setting_raw "MOD_PANGOLIN_SITE_ID" "\"$(quote_sh_value "$ID")\""
        set_setting_raw "MOD_PANGOLIN_SITE_SECRET" "\"$(quote_sh_value "$SEC")\""
            ;;
        start)
        set_setting_raw "MOD_PANGOLIN_SITE_ENABLED" "1"
            /opt/$MODNAME/etc/init start >/dev/null 2>&1
            ;;
        stop)
            /opt/$MODNAME/etc/init stop >/dev/null 2>&1
        set_setting_raw "MOD_PANGOLIN_SITE_ENABLED" "0"
            ;;
        restart)
        set_setting_raw "MOD_PANGOLIN_SITE_ENABLED" "1"
            /opt/$MODNAME/etc/init restart >/dev/null 2>&1
            ;;
        clearlog)
            printf '' > "$LOGFILE"
            ;;
    esac
fi

# Reload settings after actions.
MOD_PANGOLIN_SITE_ENABLED=0
MOD_PANGOLIN_SITE_ENDPOINT=""
MOD_PANGOLIN_SITE_ID=""
MOD_PANGOLIN_SITE_SECRET=""
[ -f "$SETTINGS" ] && . "$SETTINGS"

# ── Status ──────────────────────────────────────────────────────────────────
if is_running; then
    STATUS_TEXT="Running"
    STATUS_CLASS="running"
    DISABLED="disabled"
  SETTINGS_HINT='<div class="notice">Stop Newt first to edit settings.</div>'
else
    STATUS_TEXT="Stopped"
    STATUS_CLASS="stopped"
    DISABLED=""
    SETTINGS_HINT=""
fi

EP_ESC=$(htmlesc  "$MOD_PANGOLIN_SITE_ENDPOINT")
ID_ESC=$(htmlesc  "$MOD_PANGOLIN_SITE_ID")
SEC_ESC=$(htmlesc "$MOD_PANGOLIN_SITE_SECRET")
EP_INPUT_ESC="$EP_ESC"
[ -z "$MOD_PANGOLIN_SITE_ENDPOINT" ] && EP_INPUT_ESC="https://app.pangolin.net"

# ── Log (escape HTML and dollar signs to prevent shell expansion in heredoc) ─
LOG_HTML=""
if [ -f "$LOGFILE" ]; then
    LOG_HTML=$(tail -100 "$LOGFILE" 2>/dev/null | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g'  \
        -e 's/>/\&gt;/g'  \
        -e 's/\$/\&#36;/g')
fi

# ── Output ──────────────────────────────────────────────────────────────────
printf 'Content-type: text/html\r\n\r\n'

# Static head — split around the conditional refresh meta tag
cat << 'HEAD_START'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
HEAD_START

# Only auto-refresh while newt is running (avoids wiping settings form mid-edit)
[ "$STATUS_CLASS" = "running" ] && printf '<meta http-equiv="refresh" content="10">\n'

cat << 'STATIC_HEAD'
<title>Pangolin Site</title>
<style>
*{box-sizing:border-box}
body{margin:0;padding:8px;border-top:3px solid #79BD28;background:#fff;color:#000}
body,table,tr,td,a,input,select,textarea,button{font-family:Verdana,Arial,Helvetica,sans-serif;font-size:12px}
a{color:#004280;text-decoration:none}
a:hover{text-decoration:underline}
.topline{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.app-title{background:#004280;color:#fff;font-weight:bold;padding:6px 8px;border:1px solid #00315f;border-bottom:none}
.window{background:#f4f4f4;border:2px solid #004280;padding:0}
.section{border-top:1px solid #9fb7d5}
.section:first-child{border-top:none}
.section-head{background:#c0e0ff;color:#000;font-weight:bold;padding:5px 8px;border-bottom:1px solid #9fb7d5;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.section-body{padding:10px 8px}
.badge{display:inline-block;padding:2px 10px;border-radius:2px;color:#fff;font-weight:bold;line-height:1.4}
.running{background:#008000}
.stopped{background:#800000}
.row{display:flex;align-items:center;gap:8px;margin:6px 0}
.row label{width:90px;font-weight:bold}
.row input{width:360px;max-width:100%;padding:2px 4px;border:1px solid #7f9db9;background:#fff;height:23px}
.btn{height:24px;padding:0 10px;border:1px solid #7f9db9;background:#efefef;color:#000;cursor:pointer}
.btn:disabled{color:#777;background:#e5e5e5}
.btn + .btn{margin-left:6px}
.btn-start{border-color:#2d7a2d;background:#dff0df}
.btn-stop{border-color:#8a2c2c;background:#f7dddd}
.btn-restart{border-color:#9a6a1f;background:#f7ecd8}
.btn-save{border-color:#2e5f92;background:#dce9f8}
.hint{color:#808080;font-weight:normal}
.notice{margin:0 0 10px 0;color:#ff0000;font-style:italic}
.log{background:#fff;border:1px solid #7f9db9;color:#000;font-family:monospace;font-size:12px;line-height:1.35;padding:6px;height:300px;overflow-y:auto;white-space:pre-wrap;word-break:break-word}
</style>
</head>
<body>
<div class="topline">
<a href="/">&laquo; Back to Router</a>
</div>
<div class="app-title">Router Apps - Pangolin Site</div>
<div class="window">
STATIC_HEAD

# Status card (double-quoted heredoc — variables expand)
cat << STATUS_CARD
<div class="section">
<div class="section-head">Status</div>
<div class="section-body">
<div><span class="badge ${STATUS_CLASS}">${STATUS_TEXT}</span></div>
<div style="margin-top:8px">
<form method="post" style="display:inline">
  <input type="hidden" name="action" value="start">
  <button class="btn btn-start" type="submit">Start</button>
</form>
<form method="post" style="display:inline">
  <input type="hidden" name="action" value="stop">
  <button class="btn btn-stop" type="submit">Stop</button>
</form>
<form method="post" style="display:inline">
  <input type="hidden" name="action" value="restart">
  <button class="btn btn-restart" type="submit">Restart</button>
</form>
</div>
</div>
</div>
STATUS_CARD

# Settings card
cat << SETTINGS_CARD
<div class="section">
<div class="section-head">Settings</div>
<div class="section-body">
${SETTINGS_HINT}<form method="post">
  <input type="hidden" name="action" value="save">
  <div class="row">
    <label>Endpoint</label>
    <input type="text" name="endpoint" value="${EP_INPUT_ESC}" ${DISABLED}>
  </div>
  <div class="row">
    <label>ID</label>
    <input type="text" name="id" value="${ID_ESC}" ${DISABLED}>
  </div>
  <div class="row">
    <label>Secret</label>
    <input type="password" name="secret" value="${SEC_ESC}" ${DISABLED}>
  </div>
  <div style="margin-top:12px">
    <button class="btn btn-save" type="submit" ${DISABLED}>Save</button>
  </div>
</form>
</div>
</div>
SETTINGS_CARD

# Log card header
cat << 'LOG_HEADER'
<div class="section">
<div class="section-head">
<span>Log <span class="hint">(last 100 lines, auto-refreshes every 10s while running)</span></span>
<span style="display:inline-flex;gap:6px">
<form method="post" style="margin:0">
  <input type="hidden" name="action" value="clearlog">
  <button class="btn" type="submit">Clear Log</button>
</form>
<form method="get" style="margin:0">
  <button class="btn" type="submit">Refresh</button>
</form>
</span>
</div>
<div class="section-body">
<div class="log">
LOG_HEADER

# Log content — printed with printf to prevent any shell expansion
printf '%s' "$LOG_HTML"

# Close tags (static)
cat << 'STATIC_FOOTER'
</div>
</div>
</div>
</body>
</html>
STATIC_FOOTER
