#!/bin/sh
# jt-docker posture check (jt-wazuh-mgr rule pack jt-docker 1.0)
# License: AGPL-3.0-or-later. Author: Jason Tools.
#
# Docker API events never say whether a container is privileged, what it
# mounts from the host or which capabilities it has. This script asks the
# daemon and prints one line per running container, one line with the
# daemon version and one line per "docker info" warning, for the pack's
# decoders (rules 132680-132690). It only reads: docker info, docker ps,
# docker inspect. It changes nothing.
#
# Install on the docker host, as root, from the copy the agent group
# delivers (do not run it from /var/ossec/etc/shared: that directory is
# rewritten by the manager):
#
#   install -m 0750 -o root -g root /var/ossec/etc/shared/jt-docker-posture.sh /usr/local/sbin/
#
# and add to the agent's own ossec.conf (not the group's agent.conf, which
# would need wazuh_command.remote_commands=1 on the agent):
#
#   <wodle name="command">
#     <disabled>no</disabled>
#     <tag>jt-docker-posture</tag>
#     <command>/bin/sh /usr/local/sbin/jt-docker-posture.sh</command>
#     <interval>1h</interval>
#     <run_on_start>yes</run_on_start>
#     <timeout>120</timeout>
#     <ignore_output>no</ignore_output>
#   </wodle>
#
# Output (the decoders depend on this order; bind mounts stay last):
#   jt-docker-posture: daemon <version> security_options=<list>
#   jt-docker-posture: warning <one line of a docker info warning>
#   jt-docker-posture: container <name> <image> privileged=.. pid=.. net=..
#       ipc=.. uts=.. userns=.. cap_add=.. secopt=.. devices=.. binds=..

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
command -v docker >/dev/null 2>&1 || exit 0
docker info >/dev/null 2>&1 || exit 0

docker info --format 'jt-docker-posture: daemon {{.ServerVersion}} security_options={{join .SecurityOptions ","}}' 2>/dev/null

docker info --format '{{range .Warnings}}{{println .}}{{end}}' 2>/dev/null |
while IFS= read -r line; do
    line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -n "$line" ] && printf 'jt-docker-posture: warning %s\n' "$line"
done

# Only security-relevant SecurityOpt values are printed: an inline seccomp
# profile can be tens of kilobytes.
docker ps -q --no-trunc 2>/dev/null | xargs -r docker inspect --format \
'jt-docker-posture: container {{.Name}} {{.Config.Image}} privileged={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}} ipc={{.HostConfig.IpcMode}} uts={{.HostConfig.UTSMode}} userns={{.HostConfig.UsernsMode}} cap_add={{join .HostConfig.CapAdd ","}} secopt={{range .HostConfig.SecurityOpt}}{{if or (eq . "seccomp=unconfined") (eq . "seccomp:unconfined") (eq . "apparmor=unconfined") (eq . "apparmor:unconfined") (eq . "label=disable") (eq . "label:disable") (eq . "systempaths=unconfined") (eq . "no-new-privileges=false")}}{{.}},{{end}}{{end}} devices={{range .HostConfig.Devices}}{{.PathOnHost}},{{end}} binds={{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}:{{.Destination}}:{{if .RW}}rw{{else}}ro{{end}},{{end}}{{end}}' 2>/dev/null

exit 0
