<?php

// English version of routes_help.php: the same pages in the same order.
return [
    'Getting started' => <<<'TEXT'
A rule answers <b>"which connections to select?"</b>, and a list answers <b>"what to do with them?"</b>.

For example, the same entry <code>domain:example.com</code>:
• in <b>domains</b> sends the site through the VPN;
• in <b>block</b> blocks access;
• in <b>WARP</b> selects the WARP egress on the server.
This is how the bot's standard profiles behave; a custom template may define other actions.

<b>How to add a rule</b>
1. Go back to routes and open the list you need.
2. Tap add and answer the bot's prompt.
3. Make sure the entry appears and is enabled.
4. Refresh the subscription in the VPN app, apply the profile and test a new connection.

<b>Several sites, one per line:</b>
<code>domain:example.com
full:login.example.net
domain:example.org</code>
Or comma-separated:
<code>domain:example.com, full:login.example.net</code>

<b>With regexp:, put each expression on its own line:</b>
<code>domain:example.com
regexp:^ads[0-9]{1,3}\.example\.net$
full:login.example.org</code>
Do not append another rule to a regexp: with a comma: the comma may be part of the expression.

<b>Take only the domain from the address bar</b>
From <code>https://www.example.com:443/news?id=7</code> take <code>www.example.com</code>.
• Only this name: <code>full:www.example.com</code>.
• The main domain and all subdomains: <code>domain:example.com</code>.
Domain rules do not select a single page such as /news and do not distinguish ports.

Copy the entry itself, without quotes, comments or ✅/❌ marks. Replace example.com/example.net/example.org and the example addresses with your own.
TEXT,
    'Which list to choose' => <<<'TEXT'
<b>domains: sites through the VPN</b>
Example: <code>domain:example.com</code>.
In the standard client profile matching connections go through the VPN. Everything else usually goes direct unless other rules select it.

<b>subnet: IP addresses and networks through the VPN</b>
Example: <code>198.51.100.0/24</code>.
Enter only IPv4/IPv6 addresses, with or without a mask. A domain such as <code>example.com</code> does not fit here.

<b>block: blocking</b>
Example: <code>full:ads.example.com</code>.
Blocking applies on the Xray server and is included in the standard client profiles. Domain rules and IP/CIDR are accepted.

<b>WARP: egress from the VPN server through WARP</b>
Example: <code>domain:example.net</code>.
The client sends the selected connection into the VPN, then Xray on the server routes it through the connected WARP. Adding an entry neither connects WARP nor moves all traffic there.

<b>process / package: applications through the VPN</b>
<code>chrome.exe</code>: process name;
<code>org.telegram.messenger</code>: Android package.
They work on the side of a compatible client. Details are in the topic about applications.

<b>rule-set: ready-made lists for the client</b>
A rule source by URL for sing-box or Mihomo. The action is set in the source entry: proxy, direct, block/reject.

<b>dat: ready-made categories for the Xray server</b>
.dat files are added here. Then the category you need is referenced in block or WARP with ext:/extip:.

<b>Client and server are two stages</b>
The client is the app on a phone or computer; the server is your VPN server. A server rule sees only the traffic that reaches it. If the app bypasses the VPN, the server cannot block it or send it to WARP.
TEXT,
    'domain: and full:' => <<<'TEXT'
<b>domain: the whole name and all its subdomains</b>
<code>domain:example.com</code>
✅ example.com, www.example.com, api.example.com, a.b.example.com
❌ notexample.com, example.com.other.org, example.net
The boundary is a dot: a similar word ending is not enough.

<b>You can select only a branch of subdomains</b>
<code>domain:video.example.com</code>
✅ video.example.com, cdn.video.example.com
❌ example.com, api.example.com
Handy when only the video service inside a large site needs the VPN.

<b>No prefix means the same</b>
<code>example.com</code>
In the bot's lists this equals <code>domain:example.com</code>. There is no need to add both.

<b>full: exactly one name</b>
<code>full:example.com</code>
✅ example.com
❌ www.example.com, api.example.com

<code>full:login.example.com</code>
✅ login.example.com
❌ example.com, www.login.example.com
Use it when a rule must affect only the sign-in server.

<b>Need two names without the other subdomains?</b>
Add two separate lines:
<code>full:example.com
full:www.example.com</code>
Other names such as api.example.com are not selected by these two entries.

<b>What not to write</b>
<code>*.example.com</code>: an asterisk does not replace domain:.
<code>domain:https://example.com/path</code>: the scheme and path do not belong here.
Correct: <code>domain:example.com</code>.

Start with domain: for a whole site and full: for one name. These tasks do not need a regular expression.
TEXT,
    'keyword: substring search' => <<<'TEXT'
<b>keyword: looks for a fragment anywhere in the domain name</b>
The fragment does not have to be a separate word or subdomain.

<code>keyword:reddit</code>
✅ reddit.com, old.reddit.com, myreddit.example
❌ example.com
The rule does not check whether the site belongs to Reddit.

<code>keyword:ads</code>
✅ ads.example.com, myads.example.org, downloads.example.net
❌ metrics.example.com
The word downloads also contains the letters ads in a row. So a short word may select an ordinary site by accident.

<code>keyword:video</code>
✅ video.example.com, myvideo.example.net, videobank.example.org
❌ movies.example.com
This is a name search, not detection of video traffic.

<b>A dot does not create a domain boundary</b>
<code>keyword:example.com</code>
✅ example.com, notexample.com, example.com.other.org
For example.com itself and its subdomains use <code>domain:example.com</code>.

<b>regexp characters have no effect here</b>
<code>keyword:ads[0-9]</code> looks for the literal text ads[0-9], not ads1 or ads2. A pattern with digits needs the regexp: prefix.

Use keyword: when you really need a fragment search. Before adding one to block, think about which unrelated names may contain the same word.
TEXT,
    'regexp: reading an expression' => <<<'TEXT'
A regular expression is a pattern that checks the <b>domain name</b>. It does not look at site content, the page address, link parameters or the application name.

<b>Let's take an example apart</b>
<code>regexp:^ads[0-9]{1,3}\.example\.com$</code>
• <code>regexp:</code> tells the bot that a pattern follows.
• <code>^</code>: start of the name.
• <code>ads</code>: exactly these three letters.
• <code>[0-9]</code>: one digit.
• <code>{1,3}</code>: the previous element repeats 1 to 3 times.
• <code>\.</code>: a literal dot.
• <code>example\.com</code>: the rest of the name.
• <code>$</code>: end of the name.

✅ ads1.example.com, ads12.example.com, ads123.example.com
❌ ads.example.com, ads1234.example.com, xads1.example.com, ads1.example.com.net

<b>Useful notation</b>
<code>.</code>: any single character, including a dot.
<code>\.</code>: a dot only.
<code>*</code>: the previous element 0 or more times.
<code>+</code>: the previous element 1 or more times.
<code>?</code>: the previous element 0 or 1 time.
<code>.*</code>: any sequence, even an empty one.
<code>[a-z]</code>: one lowercase Latin letter.
<code>[a-z0-9-]</code>: one letter, digit or hyphen.
<code>[^.]</code>: one character other than a dot.
<code>{2}</code>: exactly two repetitions.
<code>(api|cdn)</code>: api or cdn.
Parentheses group part of a pattern: <code>(www\.)?</code> means an optional www.

<b>Why ^ and $ matter</b>
Without anchors the pattern matches a fragment inside the name. <code>regexp:example</code> also finds notexample.net. To check the whole name, use for example <code>regexp:^example\.com$</code>.

Enter each expression on its own line. In a message to the bot a dot needs a single backslash: <code>\.</code>.
TEXT,
    'regexp: sites and domain zones' => <<<'TEXT'
<b>1. Only one name</b>
<code>regexp:^example\.com$</code>
✅ example.com
❌ www.example.com, notexample.com
The plain variant is simpler: <code>full:example.com</code>.

<b>2. The main name and any subdomains</b>
<code>regexp:(^|\.)example\.com$</code>
✅ example.com, www.example.com, a.b.example.com
❌ notexample.com, example.com.other.org
<code>(^|\.)</code> means "start of the name or a dot before example".
The plain variant is simpler: <code>domain:example.com</code>.

<b>3. Only the main site and www</b>
<code>regexp:^(www\.)?example\.com$</code>
✅ example.com, www.example.com
❌ api.example.com, a.www.example.com
This replaces two full: lines, not all subdomains.

<b>4. All names in the .ru zone</b>
<code>regexp:.*\.ru$</code>
✅ example.ru, shop.example.ru
❌ example.ru.com, example.com
The rule selects a whole domain zone. The .ru ending does not mean the server is physically in Russia.

<b>5. Several zones</b>
<code>regexp:.*\.(ru|su)$</code>
✅ example.ru, example.su, api.example.ru
❌ example.com, example.ru.net
The | sign means "or". In block, every matching domain of these zones is blocked.

<b>6. One site in two zones, including subdomains</b>
<code>regexp:(^|\.)example\.(com|net)$</code>
✅ example.com, api.example.net, a.b.example.com
❌ example.org, notexample.com, example.net.other.org
If you only need the two main names, two full: lines will do.
TEXT,
    'regexp: subdomains and numbers' => <<<'TEXT'
<b>1. Only api and cdn of one site</b>
<code>regexp:^(api|cdn)\.example\.com$</code>
✅ api.example.com, cdn.example.com
❌ example.com, img.example.com, a.api.example.com
Two fixed names can also be two full: lines.

<b>2. Exactly one subdomain level</b>
<code>regexp:^[^.]+\.example\.com$</code>
✅ api.example.com, cdn-1.example.com
❌ example.com, a.b.example.com
<code>[^.]+</code>: one or more characters, none of them a dot.

<b>3. Any subdomain depth, but not the main name</b>
<code>regexp:^.+\.example\.com$</code>
✅ api.example.com, a.b.example.com
❌ example.com, notexample.com
Here the dot in <code>.+</code> also allows dots inside subdomains.

<b>4. Servers with a number of any length</b>
<code>regexp:^cdn[0-9]+\.example\.com$</code>
✅ cdn1.example.com, cdn42.example.com, cdn1234.example.com
❌ cdn.example.com, cdn-a.example.com
The plus requires at least one digit.

<b>5. A name without a number or with one digit</b>
<code>regexp:^ads[0-9]?\.example\.com$</code>
✅ ads.example.com, ads7.example.com
❌ ads12.example.com, bads7.example.com
The question mark applies only to the previous element [0-9].

<b>6. A number of exactly two digits</b>
<code>regexp:^img[0-9]{2}\.example\.com$</code>
✅ img01.example.com, img42.example.com
❌ img1.example.com, img123.example.com

<b>7. Two regions and numbered servers</b>
<code>regexp:^(eu|us)-cdn[0-9]{1,2}\.example\.com$</code>
✅ eu-cdn1.example.com, us-cdn12.example.com
❌ ap-cdn1.example.com, eu-cdn123.example.com

These examples select names by their shape. They do not tell what a server is for: the word ads alone does not prove it serves ads.
TEXT,
    'regexp: mistakes and limits' => <<<'TEXT'
<b>An unescaped dot</b>
<code>regexp:^example.com$</code>
Matches not only example.com but also example-com: a dot means any character.
For the exact name: <code>regexp:^example\.com$</code>.

<b>Forgot the end of the name</b>
<code>regexp:^example\.com</code>
Also matches example.com.other.org.
Add <code>$</code> if nothing may follow .com.

<b>Forgot the boundary before the domain</b>
<code>regexp:example\.com$</code>
Also matches notexample.com.
For a domain with subdomains: <code>regexp:(^|\.)example\.com$</code>.

<b>Mistook the asterisk for "any text"</b>
<code>regexp:*.example.com</code> is an invalid expression: * must follow the element it repeats.
For an ordinary site use <code>domain:example.com</code>. In regexp an arbitrary sequence is written <code>.*</code>.

<b>Did not group the alternatives</b>
<code>regexp:^api|cdn\.example\.com$</code>
Means "starts with api OR ends with cdn.example.com", so it selects even api.other.org.
For the two names you need: <code>regexp:^(api|cdn)\.example\.com$</code>.

<b>Copied unsupported syntax</b>
RE2 is used here. Lookahead/lookbehind such as <code>(?!...)</code>, <code>(?=...)</code> and backreferences <code>\1</code> are not supported.
You cannot write "the whole site except login" with a negative lookahead. It is often simpler to list the names you need; exceptions via separate actions depend on rule priority.

<b>Input format</b>
No quotes, outer /.../ or trailing /i. Write domains in lowercase: regexp is case-sensitive. Do not split one entry across lines. Do not put two regexp: on one line.

The bot checks the syntax of enabled expressions before saving, but it does not know your intent. <code>regexp:.*</code> is valid syntax and matches every domain name. Before blocking, check both the names you want and unrelated ones.
TEXT,
    'IP addresses and subnets' => <<<'TEXT'
An IP rule selects the <b>destination address</b>, not the domain name. CIDR is "address/number of network bits": the larger the number after /, the smaller the range.

<b>One IPv4 address</b>
<code>198.51.100.8</code>
Same coverage: <code>198.51.100.8/32</code>.
✅ 198.51.100.8
❌ 198.51.100.9

<b>An IPv4 /24 network</b>
<code>198.51.100.0/24</code>
Range from 198.51.100.0 to 198.51.100.255.
✅ 198.51.100.8, 198.51.100.200
❌ 198.51.101.8

<b>A smaller /25 network</b>
<code>198.51.100.0/25</code>
Range from 198.51.100.0 to 198.51.100.127.
✅ 198.51.100.100
❌ 198.51.100.200

<b>One IPv6 address</b>
<code>2001:db8::8</code>
Same coverage: <code>2001:db8::8/128</code>.
✅ 2001:db8::8
❌ 2001:db8::9

<b>An IPv6 network</b>
<code>2001:db8:1234::/48</code>
✅ 2001:db8:1234::8, 2001:db8:1234:abcd::1
❌ 2001:db8:1235::8

<b>Where to add</b>
• subnet: through the VPN in the standard profile.
• block: block the address/network.
• WARP: select the WARP egress on the server.
One per line or comma-separated. Do not add domain:/full: prefixes to IPs; no port is needed either.

IPv4 mask: 0–32, IPv6: 0–128. /33 for IPv4 and /129 for IPv6 are invalid. <code>0.0.0.0/0</code> covers all IPv4, <code>::/0</code> all IPv6; in block that is a very broad block.

One IP may serve several sites, and one site may change IPs and have IPv4 and IPv6 at once. So a domain rule is usually more convenient for a site. If the client has not yet resolved the name to an IP, how an IP rule applies depends on its DNS settings.

All 198.51.100.* and 2001:db8::* addresses here are examples: replace them with real ones.
TEXT,
    'process and package' => <<<'TEXT'
These lists select connections <b>by the application on the device</b>. In the standard sing-box/Mihomo templates the selected application goes through the VPN.

<b>process: executable process name</b>
Windows examples:
<code>chrome.exe
firefox.exe</code>
Linux examples:
<code>chrome
firefox</code>
Take the real process name from the system, not the shortcut name. Names may differ between application versions; background helpers sometimes run as separate processes.

<b>package: Android application ID</b>
Telegram example:
<code>org.telegram.messenger</code>
Chrome example:
<code>com.android.chrome</code>
A package is the technical name of the app. The label "Telegram" does not work instead. An alternative client or another build may have a different package; check it in the VPN client's app list or in the app details.

<b>How to enter</b>
One name per line or comma-separated. No domain:, full:, regexp:, links or launch parameters. These lists are for names, not regular expressions.

<b>What the client needs</b>
The VPN app must support process/package detection on your OS and have the required permissions. TUN mode is often needed to cover all device traffic; by itself it does not add missing application support.

The Xray server cannot see process names on the phone. Adding a package on the server does not make an incompatible client detect applications. These two lists are not included in the standard Xray client template.

<b>Example task</b>
To send Telegram through the VPN regardless of its server domains, add Telegram's actual package to package and refresh the profile of a compatible Android client. Higher-priority block rules can still block its connections.
TEXT,
    'rule-set: format and examples' => <<<'TEXT'
A rule-set is a ready-made set of rules the client downloads by URL. It is convenient for large lists: you do not have to maintain each entry by hand.

<b>Entry format in the bot</b>
<code>action[:type]:interval:URL</code>
Square brackets mark an optional part; do not type the brackets themselves.

<b>Action</b>
• <code>proxy</code>: send the selected connections into the VPN.
• <code>direct</code>: connect directly from the device.
• <code>block</code> or <code>reject</code>: block.
Use these values for an ordinary setup. A custom outbound name must exist exactly in your template.

<b>Update interval</b>
<code>3600</code> or <code>1h</code>: an hour;
<code>86400</code> or <code>1d</code>: a day;
<code>30m</code>: 30 minutes; <code>1w</code>: a week.
This is how often the client downloads the list, not how long the rule lasts.

<b>sing-box: sites through the VPN, daily</b>
<code>proxy:1d:https://example.org/sites.srs</code>
A ready binary list in sing-box format.

<b>sing-box: blocking, hourly</b>
<code>block:1h:https://example.org/ads.json</code>
The JSON must be a sing-box source rule-set, not arbitrary JSON.

<b>Mihomo: domains through the VPN, daily</b>
<code>proxy:domain:1d:https://example.org/sites.mrs</code>

<b>Mihomo: an IP list direct</b>
<code>direct:ipcidr:12h:https://example.org/networks.mrs</code>

<b>Mihomo: mixed blocking rules</b>
<code>reject:classical:1h:https://example.org/ads.yaml</code>

The example.org links only show the format. Replace them with direct links to real files of the right type.

Enter each source on its own line, without comma separators. Then refresh the subscription and apply the profile. The list must be downloadable from the client device.
TEXT,
    'rule-set: choosing a file' => <<<'TEXT'
<b>For sing-box</b>
• <code>.srs</code>: binary sing-box set.
• <code>.json</code>: sing-box source set.
The domain/ipcidr/classical type field is not used for this client. A suitable entry:
<code>proxy:1d:https://example.org/list.srs</code>

<b>For Mihomo</b>
<code>.yaml</code>, <code>.yml</code>, <code>.txt</code> and <code>.mrs</code> are supported. Also state what is inside:
• <code>domain</code>: domain patterns;
• <code>ipcidr</code>: IP addresses/subnets;
• <code>classical</code>: full Mihomo rules such as DOMAIN-SUFFIX or IP-CIDR.
If the type is omitted, the bot uses classical.

<b>Mihomo examples</b>
<code>proxy:domain:1d:https://example.org/domains.yaml</code>
A file with domain patterns.

<code>direct:ipcidr:1d:https://example.org/networks.txt</code>
A text file with networks.

<code>block:classical:1h:https://example.org/ads.yml</code>
YAML with a list of full rules.

<b>MRS limitation</b>
MRS supports only domain or ipcidr. The entry <code>proxy:1d:https://example.org/list.mrs</code> is wrong: without an explicit type it becomes classical. Correct:
<code>proxy:domain:1d:https://example.org/list.mrs</code>
Regular expressions in full Mihomo rules need another suitable format, such as classical YAML.

<b>Format matters more than the extension</b>
Renaming .srs to .mrs does not convert the file. The line format inside a source may differ from the domain:/full:/regexp: you type into the bot. Follow the list author's description.

Use a direct link to the file, not a GitHub viewer page. Check that it returns the list and not an HTML error. For Mihomo, MRS/YAML is preferable: a malformed TXT may be accepted as an empty set.

Choose a source for your client core: one format does not automatically suit all clients. External .dat files for the Xray server are added separately, in the dat menu.
TEXT,
    'DAT: ready-made categories' => <<<'TEXT'
.dat is a database of domain or IP categories for Xray. It is stored on the VPN server. The file is added in <b>routes → dat</b>, and the action is chosen with an entry in <b>block</b> or <b>WARP</b>.

<b>Step 1. Add a source</b>
Format:
<code>name.dat:https://direct-link-to-file</code>
Example entries:
<code>sites.dat:https://example.org/geosite.dat
networks.dat:https://example.org/geoip.dat</code>
Replace the example.org links with real HTTPS links. The first file must be in GeoSite format, the second in GeoIP. Not a renamed TXT, YAML or SRS.

<b>Step 2. Make sure the source is enabled and downloaded</b>
The dat menu lists the files under the schedule: size, download date and the reason of the last failure, if any. <b>sha256 ✅</b> means the file's checksum matched the one published next to it (<code>link.sha256sum</code>); on a mismatch the file is not replaced. A response that does not look like a .dat (an error page, an archive) is also rejected, and the previous file stays.

<b>Auto-update</b>
The <b>auto-update</b> button: preset intervals from 30 minutes to 30 days, or a <b>custom interval</b> as a number and unit, e.g. <code>90m</code>, <code>36h</code>, <code>10d</code> (15 minutes to 90 days). For intervals of a day or more you can pick the start hour: updates fall on that hour in the bot's time zone. On failure the bot notifies administrators and retries every hour until the update succeeds. The built-in databases for <code>geosite:</code> and <code>geoip:</code> entries follow the same schedule.

<b>Which categories a file has</b>
The <b>categories</b> button lists the categories of each downloaded file, with search by part of the name. The bot rejects a block or WARP entry with a category missing from the file and says why.

<b>Step 3. Choose a category and an action</b>
If sites.dat has an ads category, add to block:
<code>ext:sites.dat:ads</code>
The domains of that category are selected.

If sites.dat has a video category, you can add to WARP:
<code>ext:sites.dat:video</code>
Its domains go through the connected WARP once the traffic reaches the server.

If networks.dat has a cdn category, the IP entry is:
<code>extip:networks.dat:cdn</code>
It can also go to block or WARP, depending on the task.

<b>ext: versus extip:</b>
<code>ext:</code> selects a domain category;
<code>extip:</code> an IP category.
The file name must match the registered one, including case. The category must really exist in the file; ads/video/cdn above are only examples.

A file added without a category reference blocks nothing. If the source is disabled and the file is unavailable, the rule cannot use its contents.

These server files are not sent in the client subscription. For routing before the server use suitable client rules.

<b>geosite: and geoip:</b>
For example, <code>geosite:google</code> or <code>geoip:de</code> refer to categories of the Xray databases. They need the matching geodata where the rule runs. This is not a universal replacement for domain:/IP in every client format; the category contents depend on the database.
TEXT,
    'Enabling, import and export' => <<<'TEXT'
<b>Adding and state</b>
A new entry is added enabled. Tapping its state toggles ON/OFF. OFF keeps the entry in the list but removes it from the active rules.

Adding an entry that is already disabled does not re-enable it: enable it with the button. Delete removes the entry, and "delete all" clears the selected list.

<b>Duplicates</b>
In domain lists <code>example.com</code> and <code>domain:example.com</code> mean the same and are merged. The case of an ordinary domain name does not create a separate rule.
But <code>full:example.com</code> means something else: it does not cover subdomains.
When existing duplicates are merged, the result is enabled if at least one copy was enabled.

<b>Export</b>
Saves the list together with the states. Export before bulk editing to have a copy to restore.

<b>Import replaces the selected list entirely</b>
It does not add to the current entries. To add several rules, use the ordinary add button.

In the imported file every entry is on its own line:
<code>domain:example.com;1
full:login.example.net;0
regexp:^ads[0-9]{1,3}\.example\.com$;1</code>
<code>;1</code>: enabled; <code>;0</code>: disabled.
An old export could mark OFF with an empty value after the semicolon; that format is read too.

<b>A plain list without states</b>
<code>domain:example.com
full:login.example.net</code>
Such lines are enabled on import. Entries must fit the selected list: IP/CIDR in subnet, process names in process, and so on.

An empty file or a file without valid entries does not erase the old list. If some lines are skipped as invalid, read the bot's message: the saved set may differ from what you expected.

After an import check the contents and ON/OFF, then refresh the subscription and apply the profile on the devices.
TEXT,
    'Priority and application' => <<<'TEXT'
<b>One match is enough</b>
Two entries <code>domain:example.com</code> and <code>full:login.example.net</code> in one list select the first OR the second site. A connection does not have to match both.

<b>The order of actions is set by the profile</b>
Routing rules use the first matching action. The position of an entry on the bot's page and the order it was added in do not set its priority.

In the standard profiles blocking comes before routing through the VPN. On the server block rules are also checked before WARP.

<b>An overlap example</b>
In domains: <code>domain:example.com</code>.
In block: <code>full:ads.example.com</code>.
Result in the standard profile:
• example.com and www.example.com go through the VPN;
• ads.example.com is blocked.
The precision of full: does not give priority by itself: the order of actions does.

If block has <code>domain:example.com</code>, adding <code>full:login.example.com</code> to domains does not make an exception to the block. Change the broad rule itself, or the order/conditions in your template.

<b>When changes take effect</b>
• block/WARP are rebuilt on the Xray server when the list changes; applying may briefly interrupt connections.
• Client lists need an up-to-date profile: refresh the subscription, select/apply the updated profile and reconnect if needed.
• A single <code>vless://</code> link carries the connection parameters but not these routing lists.

Mihomo must be in rule mode. Global/Direct modes change how client rules normally apply. A custom template may also change priorities, the default outbound, or not use some list at all.

<b>Rules belong to the bot's settings</b>
Client lists are used by the profiles that include them; server lists by connections reaching Xray. These lists are not a personal setting of one selected user.

The server does not process traffic that the client sent direct. Client routing and server blocking have to be considered together.
TEXT,
    'If a rule does not work' => <<<'TEXT'
<b>1. Check the entry and the list</b>
Is the rule enabled? Is it in domains/block/WARP and not in subnet by mistake? Did https://, a port, a path or quotes slip in?

<b>2. Check the name coverage</b>
<code>full:example.com</code> does not select www.example.com.
If you need both and the other subdomains, use <code>domain:example.com</code>.
A page may load images, video and sign-in from completely different domains; add them separately when needed.

<b>3. Refresh the profile</b>
In the app refresh the subscription and apply the received configuration. Make sure this exact profile and a supported format are selected, not just an imported vless:// link.

<b>4. Check that the traffic reaches the client</b>
A system proxy does not cover every program. Full coverage may need TUN/VPN mode. In Mihomo check rule mode.

<b>5. Check the destination name and DNS</b>
A domain rule needs the client/server to know the name. A connection to a bare IP may not match it. An IP rule, conversely, may need the name resolved to an address. DNS and destination name detection in the client matter here.

<b>6. Check earlier rules</b>
If a site is both in block and domains, the standard profile blocks it. If you changed the template, check its order and default action.

<b>7. Check special dependencies</b>
For WARP: WARP connected on the server.
For rule-set: the client downloads the right file.
For dat: the file and the needed category are present.
For process/package: application detection support on your OS.

<b>How to test on a small example</b>
First use one exact rule <code>full:example.com</code> with the real domain you need. Test a new connection to it and separately to its www subdomain. Then move on to domain: or regexp:.

For <code>regexp:^ads[0-9]{1,3}\.example\.com$</code> expect:
✅ ads1.example.com, ads123.example.com
❌ ads.example.com, ads1234.example.com, ads1.example.com.net
These are pattern-test examples, not a promise that such sites exist.

Open new connections: an already open stream or a cached page does not show the effect of a new rule. The client log shows the selected rule/outbound. One external-IP test checks the route only to that test's site, not to all sites at once.
TEXT,
];
