"""CMS / web-platform fingerprint signatures.

Each signature describes how to recognize one platform from an HTTP response and
whether that platform is open-source software.

How to add a signature
-----------------------
Append a dict to SIGNATURES with:

    {
        "name": "Human readable platform name",
        "open_source": True | False,
        "matchers": {
            # every key is optional; include the ones that apply
            "header":         [(header_name, regex), ...],   # matched against response headers
            "cookie":         [regex, ...],                  # matched against Set-Cookie names/values
            "meta_generator": [regex, ...],                  # matched against <meta name=generator content=...>
            "body_path":      [substring, ...],              # literal substrings looked for in the HTML body
        },
        "weight": int,   # higher = stronger/more specific evidence (default 10)
    }

Patterns are case-insensitive. A signature matches if ANY of its matchers match;
the matcher that fired is recorded as the evidence string. When multiple
signatures match, the one with the highest weight wins as the primary platform.
"""

# --- Open-source platforms -------------------------------------------------

_DRUPAL = {
    "name": "Drupal",
    "open_source": True,
    "weight": 20,
    "matchers": {
        "header": [
            ("X-Generator", r"drupal"),
            ("X-Drupal-Cache", r".+"),
            ("X-Drupal-Dynamic-Cache", r".+"),
        ],
        "meta_generator": [r"drupal"],
        "cookie": [r"SESS[0-9a-f]{32}", r"Drupal\.visitor"],
        "body_path": ["/sites/default/files", "/core/misc/drupal.js", "/misc/drupal.js",
                      "/sites/all/", "/core/themes/", "data-drupal-"],
    },
}

_WORDPRESS = {
    "name": "WordPress",
    "open_source": True,
    "weight": 20,
    "matchers": {
        "header": [
            ("X-Powered-By", r"wordpress"),
            ("Link", r"wp-json"),
        ],
        "meta_generator": [r"wordpress"],
        "body_path": ["/wp-content/", "/wp-includes/", "/wp-json/", "wp-emoji-release"],
    },
}

_JOOMLA = {
    "name": "Joomla",
    "open_source": True,
    "weight": 20,
    "matchers": {
        "meta_generator": [r"joomla"],
        "body_path": ["/media/jui/", "/media/system/js/", "/templates/", "option=com_"],
        "cookie": [r"[0-9a-f]{32}=[0-9a-z]{26,32}"],
    },
}

_TYPO3 = {
    "name": "TYPO3",
    "open_source": True,
    "weight": 18,
    "matchers": {
        "meta_generator": [r"typo3"],
        "body_path": ["/typo3conf/", "/typo3temp/", "/fileadmin/"],
    },
}

_GHOST = {
    "name": "Ghost",
    "open_source": True,
    "weight": 18,
    "matchers": {
        "meta_generator": [r"ghost"],
        "body_path": ["/ghost/api/", "/assets/built/"],
    },
}

_DJANGO = {
    "name": "Django",
    "open_source": True,
    "weight": 8,
    "matchers": {
        "cookie": [r"csrftoken", r"django"],
    },
}

_EXPRESS = {
    "name": "Express / Node.js",
    "open_source": True,
    "weight": 8,
    "matchers": {
        "header": [("X-Powered-By", r"express")],
    },
}

# --- Proprietary platforms -------------------------------------------------

_AEM = {
    "name": "Adobe Experience Manager",
    "open_source": False,
    "weight": 20,
    "matchers": {
        "header": [("Server", r"communiqu|day-servlet-engine|adobe")],
        "body_path": ["/etc.clientlibs/", "/content/dam/", "/etc/clientlibs/",
                      "cq:", "/libs/granite/"],
    },
}

_SITECORE = {
    "name": "Sitecore",
    "open_source": False,
    "weight": 20,
    "matchers": {
        "cookie": [r"SC_ANALYTICS", r"sitecore"],
        "body_path": ["/sitecore/", "/-/media/", "sc_site="],
    },
}

_ASPNET = {
    "name": "ASP.NET (proprietary/custom)",
    "open_source": False,
    "weight": 10,
    "matchers": {
        "header": [
            ("X-AspNet-Version", r".+"),
            ("X-AspNetMvc-Version", r".+"),
            ("X-Powered-By", r"asp\.net"),
        ],
        "cookie": [r"ASP\.NET_SessionId", r"\.ASPXAUTH"],
        "body_path": ["__VIEWSTATE", "__EVENTVALIDATION", ".aspx"],
    },
}

_SQUARESPACE = {
    "name": "Squarespace",
    "open_source": False,
    "weight": 18,
    "matchers": {
        "header": [("Server", r"squarespace")],
        "body_path": ["static.squarespace.com", "squarespace.com/universal"],
    },
}

_WIX = {
    "name": "Wix",
    "open_source": False,
    "weight": 18,
    "matchers": {
        "header": [("X-Wix-Request-Id", r".+"), ("Server", r"Pepyaka")],
        "body_path": ["static.wixstatic.com", "wix.com"],
    },
}

_HUBSPOT = {
    "name": "HubSpot CMS",
    "open_source": False,
    "weight": 16,
    "matchers": {
        "header": [("X-HS-Cache-Config", r".+"), ("X-HubSpot", r".+")],
        "body_path": ["hs-scripts.com", "hsubspot", "hsforms.net"],
    },
}

# Government / vendor platforms commonly seen on public-sector sites.
_GRANICUS = {
    "name": "Granicus / GovDelivery (proprietary vendor)",
    "open_source": False,
    "weight": 14,
    "matchers": {
        "body_path": ["govdelivery.com", "granicus.com", "granicusideas"],
    },
}

# Order does not matter for matching (weight decides the winner), but keeping
# open-source entries first makes the file easy to scan.
SIGNATURES = [
    _DRUPAL, _WORDPRESS, _JOOMLA, _TYPO3, _GHOST, _DJANGO, _EXPRESS,
    _AEM, _SITECORE, _ASPNET, _SQUARESPACE, _WIX, _HUBSPOT, _GRANICUS,
]

# --- Front-end frameworks, JS libraries, analytics & third-party embeds ----
#
# Same dict shape as SIGNATURES above (name / open_source / matchers / weight),
# but semantics differ: a single site can legitimately load many of these at
# once (e.g. WordPress + jQuery + Google Analytics + Bootstrap + reCAPTCHA),
# so audit.py's match_library_signatures() collects ALL matches, never just
# the highest-weight one. `weight` is kept only for schema consistency with
# SIGNATURES and is not currently used for selection or sorting — matched
# names are sorted alphabetically for deterministic, scannable output.
# Only used when --advanced is passed; see classify() in audit.py.

_JQUERY = {
    "name": "jQuery",
    "open_source": True,
    "weight": 5,
    "matchers": {
        "body_path": ["jquery.min.js", "jquery-3.", "jquery-1.12", "code.jquery.com/jquery"],
    },
}

_JQUERY_UI = {
    "name": "jQuery UI",
    "open_source": True,
    "weight": 5,
    "matchers": {
        "body_path": ["jquery-ui.min.js", "jquery-ui.min.css"],
    },
}

_REACT = {
    "name": "React",
    "open_source": True,
    "weight": 6,
    "matchers": {
        "body_path": ["data-reactroot", "data-reactid",
                      "react-dom.production.min.js", "react.production.min.js"],
    },
}

_VUE = {
    "name": "Vue.js",
    "open_source": True,
    "weight": 6,
    "matchers": {
        "body_path": ["vue.min.js", "vue.runtime.min.js", "data-v-"],
    },
}

_ANGULAR = {
    "name": "Angular",
    "open_source": True,
    "weight": 6,
    "matchers": {
        "body_path": ["ng-version=", "angular.min.js"],
    },
}

_NEXTJS = {
    "name": "Next.js",
    "open_source": True,
    "weight": 7,
    "matchers": {
        "body_path": ["__NEXT_DATA__", "/_next/static/"],
    },
}

_GATSBY = {
    "name": "Gatsby",
    "open_source": True,
    "weight": 7,
    "matchers": {
        "body_path": ["/page-data/", "___gatsby"],
    },
}

_BOOTSTRAP = {
    "name": "Bootstrap",
    "open_source": True,
    "weight": 5,
    "matchers": {
        "body_path": ["bootstrap.min.css", "bootstrap.min.js", "bootstrap.bundle.min.js",
                      "cdn.jsdelivr.net/npm/bootstrap", "stackpath.bootstrapcdn.com/bootstrap"],
    },
}

_LODASH = {
    "name": "Lodash",
    "open_source": True,
    "weight": 4,
    "matchers": {
        "body_path": ["lodash.min.js", "lodash.js"],
    },
}

_MODERNIZR = {
    "name": "Modernizr",
    "open_source": True,
    "weight": 4,
    "matchers": {
        "body_path": ["modernizr.min.js", "modernizr-"],
    },
}

_FONT_AWESOME = {
    "name": "Font Awesome",
    "open_source": True,
    "weight": 5,
    "matchers": {
        "body_path": ["font-awesome.min.css", "fontawesome.min.css", "use.fontawesome.com",
                      "kit.fontawesome.com/", "cdnjs.cloudflare.com/ajax/libs/font-awesome"],
    },
}

_MATOMO = {
    "name": "Matomo",
    "open_source": True,
    "weight": 6,
    "matchers": {
        "body_path": ["matomo.js", "piwik.js", "matomo.php?"],
    },
}

_GOOGLE_ANALYTICS = {
    "name": "Google Analytics",
    "open_source": False,
    "weight": 6,
    "matchers": {
        "body_path": ["www.google-analytics.com/analytics.js",
                      "googletagmanager.com/gtag/js?id=G-",
                      "gtag('config', 'UA-", "gtag('config', 'G-"],
    },
}

_GOOGLE_TAG_MANAGER = {
    "name": "Google Tag Manager",
    "open_source": False,
    "weight": 6,
    "matchers": {
        "body_path": ["googletagmanager.com/gtm.js", "googletagmanager.com/ns.html", "GTM-"],
    },
}

_GOOGLE_FONTS = {
    "name": "Google Fonts",
    "open_source": False,
    "weight": 4,
    "matchers": {
        "body_path": ["fonts.googleapis.com/css", "fonts.gstatic.com"],
    },
}

_GOOGLE_MAPS = {
    "name": "Google Maps",
    "open_source": False,
    "weight": 5,
    "matchers": {
        "body_path": ["maps.googleapis.com/maps/api/js"],
    },
}

_YOUTUBE_EMBED = {
    "name": "YouTube Embed",
    "open_source": False,
    "weight": 4,
    "matchers": {
        "body_path": ["www.youtube.com/embed/", "youtube-nocookie.com/embed/"],
    },
}

_ADOBE_ANALYTICS = {
    "name": "Adobe Analytics",
    "open_source": False,
    "weight": 6,
    "matchers": {
        "body_path": ["assets.adobedtm.com", "/AppMeasurement.js", "s_code.js"],
    },
}

_CLOUDFLARE = {
    "name": "Cloudflare",
    "open_source": False,
    "weight": 8,
    "matchers": {
        "header": [("Server", r"cloudflare"), ("CF-Ray", r".+"), ("CF-Cache-Status", r".+")],
        "cookie": [r"__cf_bm", r"__cfduid", r"cf_clearance"],
    },
}

_RECAPTCHA = {
    "name": "reCAPTCHA",
    "open_source": False,
    "weight": 7,
    "matchers": {
        "body_path": ["www.google.com/recaptcha/api.js", "recaptcha/enterprise.js",
                      "g-recaptcha", "grecaptcha.render"],
    },
}

_HCAPTCHA = {
    "name": "hCaptcha",
    "open_source": False,
    "weight": 7,
    "matchers": {
        "body_path": ["hcaptcha.com/1/api.js", "h-captcha"],
    },
}

_HUBSPOT_MARKETING = {
    "name": "HubSpot Forms/Tracking",
    "open_source": False,
    "weight": 6,
    "matchers": {
        # Distinct from _HUBSPOT above (sites hosted ON HubSpot CMS) — this
        # detects HubSpot's marketing JS/forms embedded on a site hosted
        # elsewhere (e.g. a WordPress site with a HubSpot form widget).
        "body_path": ["js.hs-forms.net", "js.hs-analytics.net", "js.hs-scripts.com"],
        "cookie": [r"__hstc", r"__hssc", r"__hsfp"],
    },
}

LIBRARY_SIGNATURES = [
    _JQUERY, _JQUERY_UI, _REACT, _VUE, _ANGULAR, _NEXTJS, _GATSBY, _BOOTSTRAP,
    _LODASH, _MODERNIZR, _FONT_AWESOME, _MATOMO,
    _GOOGLE_ANALYTICS, _GOOGLE_TAG_MANAGER, _GOOGLE_FONTS, _GOOGLE_MAPS,
    _YOUTUBE_EMBED, _ADOBE_ANALYTICS, _CLOUDFLARE, _RECAPTCHA, _HCAPTCHA,
    _HUBSPOT_MARKETING,
]

# Marker paths probed only when --probe is passed and the primary fetch was
# inconclusive. Kept small and polite. Maps a path to (platform_name, open_source).
PROBE_PATHS = [
    ("/wp-json/", "WordPress", True),
    ("/wp-login.php", "WordPress", True),
    ("/core/misc/drupal.js", "Drupal", True),
    ("/user/login", "Drupal", True),
    ("/administrator/", "Joomla", True),
]
