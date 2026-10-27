# Lab setup

This lab generates real authentication and web logs for the detector to analyze. Use it only on machines you own.

## Machines

- **Target:** Ubuntu VM running the OpenSSH server and Nginx.
- **Attacker:** Kali Linux VM on the same network.
- **Analyzer:** the Windows PC running this project, or the target VM with a copy of the project.

Both VMs ran on VMware Workstation using NAT networking.

## Target setup (Ubuntu)

```bash
sudo apt update
sudo apt install -y openssh-server nginx
sudo systemctl enable --now ssh nginx

# A folder Nginx refuses to serve, to produce 403 responses.
sudo mkdir -p /var/www/html/private
```

Check the target's IP address with `hostname -I`. Ubuntu writes SSH events to `/var/log/auth.log` and web requests to `/var/log/nginx/access.log`.

## Attacks (run from Kali against the target only)

| Scenario | Command | Expected alert |
|---|---|---|
| SSH brute force | `hydra -l admin -P passwords.txt -t 4 -f ssh://<target-ip>` | `brute_force` (High) |
| Password spraying | `hydra -L users.txt -p <one-password> -t 4 ssh://<target-ip>` | `password_spraying` (High) |
| Compromise | six failed logins for a real user, then a correct login | `compromise_indicator` (Critical) |
| HTTP scanning | a loop requesting 35 missing pages with `curl` | `scanning` (Medium) |
| Access denied | 12 `curl` requests to `/private/` | `unauthorized_access` (High) |

Use short password and username lists that you create yourself. Don't use real credentials.

## Collecting the logs

The logs in `/var/log` are readable only by root. Copy them to a file your user can read:

```bash
sudo cp /var/log/auth.log ~/auth_lab.log && sudo chown $USER ~/auth_lab.log
sudo cp /var/log/nginx/access.log ~/access_lab.log && sudo chown $USER ~/access_lab.log
```

Copy the files to the analyzing machine, and run:

```powershell
python -m src.ids.cli auth_lab.log --type auth
python -m src.ids.cli access_lab.log --type http
```

## Live demo

On the target, run the monitor as root so it can read `auth.log`:

```bash
sudo python3 -m src.ids.cli /var/log/auth.log --type auth --follow --from-end
```

Then run an attack from Kali. The alert prints on the target within seconds.

## Things that differ from the sample data

- Ubuntu writes ISO-8601 timestamps, like `2026-10-25T16:19:33+00:00`.
- rsyslog collapses repeated lines into `message repeated N times`. The parser expands these.
- Your logs contain system messages (cron, sudo, PAM) as well. The detector counts these as lines it doesn't analyze.
