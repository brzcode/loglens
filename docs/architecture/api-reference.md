# API Reference

### External APIs Consumed

#### AbuseIPDB API

  * **Purpose:** To enrich suspicious IP addresses with threat intelligence context.
  * **Base URL(s):** `https://api.abuseipdb.com/api/v2/`
  * **Authentication:** API Key sent in the `Key` header. Key will be stored in an environment variable (`ABUSEIPDB_API_KEY`).
  * **Key Endpoints Used:**
      * **`GET /check`**:
          * Description: Retrieves information and reputation score for a given IP address.
          * Request Parameters: `ipAddress` (string), `maxAgeInDays` (integer, e.g., 90)
          * Success Response Schema (Code: `200 OK`):
            ```json
            {
              "data": {
                "ipAddress": "1.2.3.4",
                "countryCode": "US",
                "abuseConfidenceScore": 95,
                "isTor": false
              }
            }
            ```
          * Note: The actual schema is more complex; this is the subset of data we will use.
  * **Rate Limits:** Free tier has a limit of 1,000 requests per day. The application must be mindful of this.
  * **Link to Official Docs:** `https://docs.abuseipdb.com/`
