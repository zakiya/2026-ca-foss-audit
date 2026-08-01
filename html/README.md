# CSV column descriptions

For audit.csv

`hostname-cleaned`
The normalized domain or subdomain of a California government web site (e.g., edd.ca.gov.)

`canonical-to-text`
The canonical URL the hostname resolves to, expressed as plain text.

`ga-total-views`
Total Google Analytics page views for the hostname across the measurement period. Used as a proxy for public-facing traffic volume. Higher-traffic sites represent broader public impact.

`techstack-status`
The HTTP status code the hostname returned when the scanner crawled it. A blank value means the scanner was not run on this hostname

Only sites returning 200 could have their platform identified.

`techstack-opensource-platform`
Whether the detected platform is open source. Values:

- `yes` — confirmed open-source platform
- `no` — confirmed proprietary platform
- `unknown` — site was reachable but platform could not be identified
- `error` — site was unreachable during scanning
- `blank` — not scanned

`techstack-platform`
The specific CMS or web platform detected. Sites that returned a non-200 status or where detection was inconclusive are marked undetermined.

`techstack-frameworks`
Third-party JavaScript libraries and tools detected on the page. Blank where none were detected or the site was not scanned.