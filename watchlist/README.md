# GeoIP Watchlist

The map enriches attacker IPs by joining them against a geoip watchlist in Sentinel.

## The size constraint

Microsoft Sentinel watchlists uploaded through the portal are capped at **3.8 MB**. A full
city-level IPv4 geolocation database (MaxMind GeoLite2) is ~191–245 MB; a full-coverage
country-level version is still ~25 MB. Both exceed the portal limit and would require the
Azure Storage + SAS-URL "large watchlist" path.

## The approach used here

The GeoLite2 City dataset was summarized to **one dominant location per /16 block**,
retaining full IPv4 coverage and city-level labels while collapsing to ~56,000 rows
(~2.6 MB) — small enough for the simple portal drag-and-drop upload.

- File: `geoip-city-portal.csv`
- Columns: `network, city_name, country_name, latitude, longitude`
- Import: Sentinel → Configuration → Watchlists → + New → alias `geoip`,
  **SearchKey = `network`**, upload the CSV.

## Tradeoff

`/16` granularity means each block is tagged with its *dominant* city, so IPs near block
boundaries may attribute to the largest nearby city rather than their exact one. For a
brute-force **origin** map, broad geographic spread matters more than pinpoint accuracy,
so this is an acceptable trade for staying within the portal upload limit.
