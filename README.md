# Day-28-Investigating-a-Mythic-C2-Framework

By the end of this challenge, you’ll know how to investigate a common C2 (Command and Control) framework called Mythic and what telemetry to look for during an investigation. Specifically, we will dive into the agent named `svchost-aurora.exe` and trace its activities in our Elastic environment.

Let’s get started!

## Step 1: Initial Investigation — Discovering the Agent
To begin, head over to your Elastic Web GUI, click the hamburger icon, and navigate to Discover. Make sure to set the time frame to 30 days. Then search for the Mythic C2 agent `svchost-aurora.exe` (or whatever name your agent might be using in your environment).

Let’s start investigating the chain of events. Imagine, for the sake of practice, that we didn’t already know the agent’s name was `svchost-aurora.exe`. How would we identify a C2 agent?

## Step 2: Identifying C2 Activity
There are a few ways to detect a C2 framework in operation:

1. **Network Telemetry**  
   C2 sessions often have a lot of back-and-forth traffic, typically reflected in the top 10 talkers — IP addresses that have the most bytes transferred.  
   Check for unusual traffic patterns, especially connections involving high data exchange, indicating potential malicious activity.

2. **Heartbeat Activity**  
   Look for periodic heartbeat-like network connections. C2 frameworks often maintain persistent communication with the attacker, sending regular check-ins.

3. **Process Creations**  
   If you have Sysmon telemetry, use event ID 3 to track network creations and process executions. Look for processes like `rundll32.exe`, often used by malware to load DLL files for execution.

## Step 3: Using Dashboards to Analyze Process Activity
Let’s leverage the dashboards we created in previous challenge:

- Click the hamburger icon, go to Dashboards under Analytics, and select the **Pheonix-Suspicious Activity** dashboard.  
- Make sure the time frame is set to 30 days.

At the top of this dashboard, we can see a list of process creations like `Powershell`, `cmd.exe`, and `rundll32.exe`. I pay close attention to `rundll32.exe`, as it is often used by malware to load DLLs and execute malicious activities.

In this case, I found an unusual executable under the directory `C:\Users\Public\Downloads`. Even if it wasn’t called `svchost-aurora.exe` and instead something more generic like `update.exe`, I would still investigate it. The reason? Executables in public directories initiating connections to external IP addresses — especially on port 80 — raise red flags.

## Step 4: Diving Deeper — Timeline of Events
Now, let’s pretend we’re doing a threat hunt and stumbled upon an outbound Powershell connection that looks suspicious. Here’s how we’ll investigate further:

Copy the destination IP from the suspicious connection and search for it in Elastic Discover using the following query:

```plaintext
event.code: 3 AND winlog.event_data.DestinationIp: <Your Destination IP>
```

## Building a Timeline of Events

We can now build a timeline of events:

- **Sep 21, 2024 @ 19:05:22.093**: A network connection was initiated towards the destination IP.
- **Sep 21, 2024 @ 19:08:48.730**: The connection continued.

If you have Sysmon telemetry, check the process GUID for correlation. The process GUID will help track all events related to the PowerShell session.

### File Creation and Execution

- **Sep 21, 2024 @ 19:05:21.104**: Event Code 11 (File Created) — A file named `svchost-Pheonixrocks.exe` was created in `C:\Users\Public\Downloads` using a PowerShell terminal.
- **Sep 21, 2024 @ 19:05:23.610**: Event Code 29 (File Executed) — The file `svchost-Pheonixrocks.exe` was executed from the Downloads folder.

Using SHA1 hash values, we can further investigate the file’s identity and behavior. This hash will help in tracking the origin and other instances of the file across the system.

## Step 5: Correlating the Process Chain

The process GUID from `svchost-Pheonixrocks.exe` allows us to backtrack the event chain. Initially, we discovered the PowerShell session, and now we can see that this session was responsible for retrieving and executing `svchost-Pheonixrocks.exe`.

Let’s use this process GUID to identify related processes:

- I’ll search for the Process ID (PID): `4460`.
- The Parent Process ID: `3376` tells me that the PowerShell process initiated this activity.

Even though this process doesn’t appear to have spawned additional child processes, we can look for specific actions we know occurred. For example, we had a file named `passwords.txt` that was opened using Notepad.

By searching for `passwords.txt`, we found an event showing `Explorer.exe` as the parent process, and the command line showing `Notepad.exe` was used to view the file.

## Step 6: Creating a Ticket for the Mythic C2 Alert

Now that we’ve investigated the Mythic C2 activity, it’s time to create an alert ticket in OS Ticket for proper tracking and further analysis.

Here’s how to set it up:

1. **Navigate to Rules**: Go to the Rules section in Elastic and locate the rule for **Pheonix-Mythic-C2-Apollo-Agent-Detected**.
2. **Edit the Rule**: Click on Edit Rule Settings and navigate to the Actions tab.
3. **Select Webhook**: Choose the Webhook option, configure the body code for alert arrangements, and click Save Changes.
4. **Set the Frequency**: Ensure the rule is scheduled to run every 1 minute by adjusting the Schedule settings.

Now, every Mythic C2 alert will automatically create a ticket in your OS Ticket system for easy tracking and resolution.

## Conclusion: Wrapping Up the Investigation

In this Challenge, we peeled back the layers of a Mythic C2 agent, following its trail from initial network connections to suspicious process creations and file executions. By diving into the telemetry and piecing together the timeline, we built a clear picture of the C2 activity lurking within the system.

We didn’t stop there — we took it a step further by automating our defense, setting up a webhook in OS Ticket to ensure every future alert is swiftly documented and tracked for action.

But the investigation doesn’t end here! In the next challenge, we’ll explore how to install and configure Elastic EDR (Elastic Defend) to add another layer of protection and wrap up our 30-day SOC challenge on a high note. The journey continues, so stay tuned for more insights and powerful tools to secure your environment!
