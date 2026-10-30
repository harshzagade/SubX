"""Subdomain-takeover hints from already-resolved CNAME aliases.

When a subdomain's CNAME points at a third-party hosting service
(GitHub Pages, Heroku, AWS S3, ...), the subdomain is only as alive
as that hosted resource: if the resource was deleted but the DNS
record left behind, anyone can re-claim the name and serve content
on the victim's subdomain. That is a subdomain takeover.

This module does purely local pattern matching on the CNAME alias
that validation already resolved -- no extra requests are made, and
a match is only a *hint*: it says "this alias belongs to a service
where dangling records are a known takeover vector", not "this
subdomain is takeable". Confirming a takeover needs a separate
check that the hosted resource is actually gone (e.g. the service's
"not found" page), which SubX deliberately does not do.
"""

#: (suffix, service) pairs, most specific first. Matching is suffix
#: based: an alias matches when it equals the suffix or ends with
#: "." + suffix, so "evilgithub.io" and "github.io.evil.com" do NOT
#: match "github.io", but "user.github.io" does. Generic suffixes
#: (e.g. "amazonaws.com") sit after their specific siblings so the
#: more precise service name wins.
TAKEOVER_FINGERPRINTS = (
    ("s3.amazonaws.com", "AWS S3"),
    ("s3-website.amazonaws.com", "AWS S3"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    ("cloudfront.net", "AWS CloudFront"),
    ("amazonaws.com", "AWS"),
    ("azurewebsites.net", "Azure App Service"),
    ("azureedge.net", "Azure CDN"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("blob.core.windows.net", "Azure Blob Storage"),
    ("cloudapp.net", "Azure Cloud Services"),
    ("cloudapp.azure.com", "Azure"),
    ("github.io", "GitHub Pages"),
    ("gitlab.io", "GitLab Pages"),
    ("bitbucket.io", "Bitbucket Cloud"),
    ("herokuapp.com", "Heroku"),
    ("fastlylb.net", "Fastly"),
    ("fastly.net", "Fastly"),
    ("netlify.app", "Netlify"),
    ("vercel.app", "Vercel"),
    ("now.sh", "Vercel"),
    ("pantheonsite.io", "Pantheon"),
    ("wordpress.com", "WordPress.com"),
    ("blogspot.com", "Blogger"),
    ("shopify.com", "Shopify"),
    ("squarespace.com", "Squarespace"),
    ("webflow.io", "Webflow"),
    ("wixsite.com", "Wix"),
    ("weebly.com", "Weebly"),
    ("strikingly.com", "Strikingly"),
    ("ghost.io", "Ghost(Pro)"),
    ("zendesk.com", "Zendesk"),
    ("freshdesk.com", "Freshdesk"),
    ("statuspage.io", "Atlassian Statuspage"),
    ("uservoice.com", "UserVoice"),
    ("mybigcommerce.com", "BigCommerce"),
    ("bigcartel.com", "Big Cartel"),
    ("smugmug.com", "SmugMug"),
    ("tumblr.com", "Tumblr"),
)


def normalize_alias(alias):
    """Canonical form of a CNAME alias for suffix matching."""
    if not alias:
        return ""
    return alias.strip().rstrip(".").lower()


def takeover_hint(alias):
    """Return the service name when ``alias`` points at a known
    takeover-prone hosting service, else ``None``.

    Matching is suffix based (see TAKEOVER_FINGERPRINTS): the alias
    must equal the service suffix or be a subdomain of it. Returns
    ``None`` for empty aliases and for services not in the list --
    "no hint" never means "safe", only "not a known pattern".
    """
    name = normalize_alias(alias)
    if not name:
        return None
    for suffix, service in TAKEOVER_FINGERPRINTS:
        if name == suffix or name.endswith("." + suffix):
            return service
    return None
