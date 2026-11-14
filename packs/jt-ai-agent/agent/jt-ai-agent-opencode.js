// jt-ai-agent: opencode plugin that hands every tool call and new session to the
// pack's audit hook (/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py --agent opencode),
// which writes one redacted JSON line to /var/log/jt-ai-agent/actions.log for Wazuh.
// Part of the jt-ai-agent rule pack (jt-wazuh-mgr). AGPL-3.0-or-later, Jason Tools Co., Ltd.
//
// Install as /etc/opencode/plugins/jt-ai-agent.js (opencode loads the system directory's
// plugins for every user; ~/.config/opencode/plugins/ for one user). Works with opencode 2.x
// (setup(ctx): ctx.tool.hook("execute.before"), ctx.event.subscribe) and 1.x (server()).
//
// Like the hook it never blocks or changes anything: it does not await the hook, ignores
// every error, and passes the tool input on unchanged. The input goes to the hook on stdin
// only; secrets are removed there, and file contents and prompts are never written.

import { spawn } from "node:child_process"
import { existsSync } from "node:fs"

const HOOK = "/usr/local/lib/jt-ai-agent/jt-ai-agent-hook.py"

function send(event) {
  try {
    if (!existsSync(HOOK)) return
    const child = spawn(HOOK, ["--agent", "opencode"], { stdio: ["pipe", "ignore", "ignore"] })
    child.on("error", () => {})
    child.stdin.on("error", () => {})
    child.stdin.end(JSON.stringify(event))
    if (typeof child.unref === "function") child.unref()
  } catch (e) {}
}

function pick(obj, ...keys) {
  for (const k of keys) {
    if (obj && typeof obj[k] === "string" && obj[k]) return obj[k]
  }
  return undefined
}

function toolEvent(ev, args, directory) {
  return {
    hook_event_name: "PreToolUse",
    tool_name: pick(ev, "tool", "name", "toolName"),
    tool_input: args && typeof args === "object" ? args : {},
    session_id: pick(ev, "sessionID", "sessionId") || pick(ev.session || {}, "id"),
    tool_use_id: pick(ev, "callID", "callId", "id"),
    cwd: pick(ev, "directory", "cwd") || directory,
  }
}

// One SessionStart line per session: only "session.created" events count (2.0.32 was seen to
// deliver other events through a filtered subscription), and each session ID is sent once.
const seenSessions = new Set()

function sessionEvent(event, directory) {
  if (!event || event.type !== "session.created") return undefined
  const p = event.properties || event.data || event
  const info = p.info || p.session || p
  const id = pick(info, "id", "sessionID", "sessionId") || pick(p, "sessionID", "sessionId", "id")
  if (!id || seenSessions.has(id)) return undefined
  seenSessions.add(id)
  if (seenSessions.size > 10000) seenSessions.clear()
  return {
    hook_event_name: "SessionStart",
    source: "startup",
    session_id: id,
    cwd: pick(info, "directory", "cwd") || directory,
  }
}

export default {
  id: "jt-ai-agent",
  // opencode 2.x
  async setup(ctx) {
    const directory = (ctx.location && ctx.location.directory) || process.cwd()
    try {
      await ctx.tool.hook("execute.before", (ev) => {
        try { send(toolEvent(ev, ev.input !== undefined ? ev.input : ev.args, directory)) } catch (e) {}
      })
    } catch (e) {}
    // 1.2: failed calls only (a successful one is already on record from execute.before)
    try {
      await ctx.tool.hook("execute.after", (ev) => {
        try {
          if (ev && ev.status === "error") {
            const e = toolEvent(ev, ev.input !== undefined ? ev.input : ev.args, directory)
            e.hook_event_name = "PostToolUseFailure"
            e.error = ev.error && ev.error.message ? String(ev.error.message) : "error"
            send(e)
          }
        } catch (e) {}
      })
    } catch (e) {}
    const controller = new AbortController()
    void (async () => {
      try {
        for await (const event of ctx.event.subscribe({ types: ["session.created", "permission.asked"], signal: controller.signal })) {
          try {
            if (event && event.type === "permission.asked") {
              const p = event.properties || event.data || event
              send({ hook_event_name: "PermissionRequest", tool_name: pick(p, "tool", "type", "permission"),
                     session_id: pick(p, "sessionID", "sessionId"), cwd: directory, tool_input: {} })
              continue
            }
            const e = sessionEvent(event, directory); if (e) send(e)
          } catch (e) {}
        }
      } catch (e) {}
    })()
    return () => controller.abort()
  },
  // opencode 1.x
  async server(input) {
    const directory = (input && input.directory) || process.cwd()
    return {
      "tool.execute.before": async (info, output) => {
        try { send(toolEvent(info || {}, output && output.args, directory)) } catch (e) {}
      },
      event: async ({ event }) => {
        try { const e = sessionEvent(event, directory); if (e) send(e) } catch (e) {}
      },
    }
  },
}
