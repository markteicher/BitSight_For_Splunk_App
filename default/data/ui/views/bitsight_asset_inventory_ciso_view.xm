<?xml version="1.0"?>
<!--
=============================================================================
File Name:
    bitsight_asset_inventory_ciso_view.xml

View Name:
    BitSight Asset Inventory – Executive (CISO)

Version:
    1.0.0
=============================================================================

PURPOSE

Provide a clear, complete view of BitSight asset data so a CISO or auditor
can understand the organization’s external assets, where they are located,
who is responsible for them, and how long they have existed.

WHAT THIS VIEW SHOWS

- Total number of assets
- Active versus inactive assets
- Countries where assets are located
- Ownership or responsibility for each asset
- How long assets have been present
- Size of network ranges (CIDR)

DATA SOURCE

bitsight_with_full_whois.csv

PRIMARY KEY

Value (IP address or CIDR range)

AGE CALCULATION

Age is calculated from Start Date to current date.

=============================================================================
-->
<dashboard version="1.1">

  <!-- BASE SEARCH -->
  <search id="base_bitsight">
    <query>
      | inputlookup bitsight_with_full_whois.csv
      | eval start_epoch = strptime('Start Date', "%Y-%m-%d")
      | eval age_days = floor((now() - start_epoch)/86400)
      | eval age_bucket = case(
          age_days < 30, "0-29d",
          age_days < 60, "30-59d",
          age_days < 90, "60-89d",
          age_days < 180, "90-179d",
          age_days < 365, "180-364d",
          age_days < 730, "1y",
          age_days < 1095, "2y",
          age_days < 1460, "3y",
          age_days < 1825, "4y",
          age_days < 2190, "5y",
          age_days >= 2190, "5y+"
      )
    </query>
  </search>

  <!-- ROW 1 -->
  <row>
    <panel>
      <title>Total Assets</title>
      <single>
        <search base="base_bitsight">
          <query>| stats count as "Total Assets"</query>
        </search>
      </single>
    </panel>

    <panel>
      <title>Active vs Inactive</title>
      <table>
        <search base="base_bitsight">
          <query>
            | stats count by "Is Active"
            | sort - count
          </query>
        </search>
      </table>
    </panel>
  </row>

  <!-- ROW 2 -->
  <row>
    <panel>
      <title>Geographic Distribution</title>
      <table>
        <search base="base_bitsight">
          <query>
            | stats count by Country
            | sort - count
          </query>
        </search>
      </table>
    </panel>

    <panel>
      <title>Ownership Distribution</title>
      <table>
        <search base="base_bitsight">
          <query>
            | stats count by "Attributed To"
            | sort - count
          </query>
        </search>
      </table>
    </panel>
  </row>

  <!-- ROW 3 -->
  <row>
    <panel>
      <title>Asset Age Distribution</title>
      <table>
        <search base="base_bitsight">
          <query>
            | stats count by age_bucket
          </query>
        </search>
      </table>
    </panel>

    <panel>
      <title>Largest Network Ranges</title>
      <table>
        <search base="base_bitsight">
          <query>
            | sort - "CIDR Size"
            | head 10
            | table Value "CIDR Size" "Attributed To" Country
          </query>
        </search>
      </table>
    </panel>
  </row>

  <!-- ROW 4 -->
  <row>
    <panel>
      <title>Detailed Asset View</title>
      <table>
        <search base="base_bitsight">
          <query>
            | sort 0 "Start Date"
          </query>
        </search>
      </table>
    </panel>
  </row>

</dashboard>
