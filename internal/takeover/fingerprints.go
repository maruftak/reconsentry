package takeover

// Fingerprints is a curated subset of EdOverflow's can-i-take-over-xyz data
// (cross-checked against subjack and nuclei's http/takeovers templates). It is
// embedded so the binary stays self-contained — no network fetch at runtime.
//
// Three groups, in priority order:
//
//  1. HTTP-fingerprint, claimable (Vulnerable=true): the service serves a
//     recognizable "unclaimed" page and the resource can be re-registered.
//  2. NXDOMAIN, claimable (NXDOMAIN=true, Vulnerable=true): no body fingerprint;
//     the signal is the CNAME target no longer resolving.
//  3. Parked, NOT claimable (Vulnerable=false): the service returns a
//     recognizable 404 but blocks re-registration. Reported as info only, never
//     as a takeover, so a hunter isn't sent chasing a dead end.
//
// CNAME patterns are matched as DNS suffixes (no leading dot). Body strings are
// verbatim. Providers occasionally change their 404 copy, so refresh this table
// against can-i-take-over-xyz periodically.
var Fingerprints = []Fingerprint{
	// --- HTTP-fingerprint, claimable -----------------------------------------
	{Service: "AWS/S3", CNAMEs: []string{"s3.amazonaws.com", "s3-website.amazonaws.com"}, Body: "The specified bucket does not exist", Vulnerable: true},
	{Service: "Bitbucket", CNAMEs: []string{"bitbucket.io"}, Body: "Repository not found", Vulnerable: true},
	{Service: "Cargo Collective", CNAMEs: []string{"cargocollective.com"}, Body: "<div class=\"notfound\">", Vulnerable: true},
	{Service: "Ghost", CNAMEs: []string{"ghost.io"}, Body: "Site unavailable", Vulnerable: true},
	{Service: "Help Scout", CNAMEs: []string{"helpscoutdocs.com"}, Body: "No settings were found for this company:", Vulnerable: true},
	{Service: "HelpJuice", CNAMEs: []string{"helpjuice.com"}, Body: "We could not find what you're looking for.", Vulnerable: true},
	{Service: "Pantheon", CNAMEs: []string{"pantheonsite.io"}, Body: "404 error unknown site!", Vulnerable: true},
	{Service: "Readme.io", CNAMEs: []string{"readme.io"}, Body: "Project doesnt exist... yet!", Vulnerable: true},
	{Service: "Strikingly", CNAMEs: []string{"s.strikinglydns.com"}, Body: "PAGE NOT FOUND.", Vulnerable: true},
	{Service: "Surge.sh", CNAMEs: []string{"surge.sh"}, Body: "project not found", Vulnerable: true},
	{Service: "SurveySparrow", CNAMEs: []string{"surveysparrow.com"}, Body: "Account not found.", Vulnerable: true},
	{Service: "Tilda", CNAMEs: []string{"tilda.ws"}, Body: "Please renew your subscription", Vulnerable: true},
	{Service: "Uberflip", CNAMEs: []string{"read.uberflip.com"}, Body: "The URL you've accessed does not provide a hub.", Vulnerable: true},
	{Service: "WordPress.com", CNAMEs: []string{"wordpress.com"}, Body: "Do you want to register", Vulnerable: true},
	{Service: "Agile CRM", CNAMEs: []string{"agilecrm.com"}, Body: "Sorry, this page is no longer available.", Vulnerable: true},
	{Service: "Anima", CNAMEs: []string{"animaapp.io"}, Body: "The page you were looking for does not exist.", Vulnerable: true},
	{Service: "Gemfury", CNAMEs: []string{"furyns.com"}, Body: "404: This page could not be found.", Vulnerable: true},
	{Service: "HatenaBlog", CNAMEs: []string{"hatenablog.com"}, Body: "404 Blog is not found", Vulnerable: true},
	{Service: "JetBrains/YouTrack", CNAMEs: []string{"myjetbrains.com", "youtrack.cloud"}, Body: "is not a registered InCloud YouTrack", Vulnerable: true},
	{Service: "Pingdom", CNAMEs: []string{"stats.pingdom.com"}, Body: "Sorry, couldn't find the status page", Vulnerable: true},
	{Service: "UptimeRobot", CNAMEs: []string{"stats.uptimerobot.com"}, Body: "page not found", Vulnerable: true},
	{Service: "Canny", CNAMEs: []string{"canny.io"}, Body: "There is no such company. Did you enter the right URL?", Vulnerable: true},
	{Service: "Big Cartel", CNAMEs: []string{"bigcartel.com"}, Body: "<h1>Oops! We could&#8217;t find that page.</h1>", Vulnerable: true},
	{Service: "Campaign Monitor", CNAMEs: []string{"createsend.com"}, Body: "Double check the URL or <a href=\"mailto:help@createsend.com", Vulnerable: true},
	{Service: "KickoffLabs", CNAMEs: []string{"kickofflabs.com"}, Body: "Landing Page Not Found", Vulnerable: true},

	// --- NXDOMAIN, claimable (no body fingerprint) ---------------------------
	{Service: "AWS/Elastic Beanstalk", CNAMEs: []string{"elasticbeanstalk.com"}, NXDOMAIN: true, Vulnerable: true},
	{Service: "Microsoft Azure (App Service)", CNAMEs: []string{"azurewebsites.net"}, NXDOMAIN: true, Vulnerable: true},
	{Service: "Microsoft Azure (Blob)", CNAMEs: []string{"blob.core.windows.net"}, NXDOMAIN: true, Vulnerable: true},
	{Service: "Microsoft Azure (Cloud App)", CNAMEs: []string{"cloudapp.net", "cloudapp.azure.com"}, NXDOMAIN: true, Vulnerable: true},
	{Service: "Microsoft Azure (Traffic Manager)", CNAMEs: []string{"trafficmanager.net"}, NXDOMAIN: true, Vulnerable: true},
	{Service: "Discourse", CNAMEs: []string{"trydiscourse.com"}, NXDOMAIN: true, Vulnerable: true},
	{Service: "LaunchRock", CNAMEs: []string{"launchrock.com"}, NXDOMAIN: true, Vulnerable: true},
	{Service: "SmugMug", CNAMEs: []string{"domains.smugmug.com"}, NXDOMAIN: true, Vulnerable: true},

	// --- Parked, NOT claimable (info only) -----------------------------------
	{Service: "GitHub Pages", CNAMEs: []string{"github.io"}, Body: "There isn't a GitHub Pages site here.", Vulnerable: false},
	{Service: "Heroku", CNAMEs: []string{"herokudns.com", "herokuapp.com", "herokussl.com"}, Body: "No such app", Vulnerable: false},
	{Service: "Shopify", CNAMEs: []string{"myshopify.com"}, Body: "Sorry, this shop is currently unavailable.", Vulnerable: false},
	{Service: "Fastly", CNAMEs: []string{"fastly.net"}, Body: "Fastly error: unknown domain:", Vulnerable: false},
	{Service: "Tumblr", CNAMEs: []string{"domains.tumblr.com"}, Body: "Whatever you were looking for doesn't currently exist at this address.", Vulnerable: false},
	{Service: "Unbounce", CNAMEs: []string{"unbouncepages.com"}, Body: "The requested URL was not found on this server.", Vulnerable: false},
	{Service: "Webflow", CNAMEs: []string{"proxy.webflow.com", "proxy-ssl.webflow.com"}, Body: "The page you are looking for doesn't exist or has been moved.", Vulnerable: false},
	{Service: "Wix", CNAMEs: []string{"wixdns.net"}, Body: "Looks Like This Domain Isn't Connected To A Website Yet!", Vulnerable: false},
	{Service: "Intercom", CNAMEs: []string{"custom.intercom.help"}, Body: "Uh oh. That page doesn't exist.", Vulnerable: false},
	{Service: "Zendesk", CNAMEs: []string{"zendesk.com"}, Body: "Help Center Closed", Vulnerable: false},
	{Service: "Acquia", CNAMEs: []string{"acquia-sites.com"}, Body: "Web Site Not Found", Vulnerable: false},
	{Service: "Netlify", CNAMEs: []string{"netlify.app", "netlify.com"}, Body: "Not Found - Request ID:", Vulnerable: false},
}
