import os
import logging
import geoip2.database
import ipaddress

logger = logging.getLogger(__name__)

# Paths to the MaxMind GeoLite2 databases
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "GeoLite2-Country.mmdb"
)
ASN_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "GeoLite2-ASN.mmdb"
)


class GeoIPManager:
    def __init__(self):
        self.reader = None
        self.asn_reader = None
        self._load_db()

    def _load_db(self):
        # 1. Load Country DB
        if not os.path.exists(DB_PATH):
            logger.warning(
                f"GeoIP Country database not found at {DB_PATH}. Geolocation lookups will be disabled."
            )
        else:
            try:
                self.reader = geoip2.database.Reader(DB_PATH)
                logger.info("Successfully loaded MaxMind GeoLite2-Country database.")
            except Exception as e:
                logger.error(f"Failed to load GeoIP Country database: {e}")

        # 2. Load ASN DB
        if not os.path.exists(ASN_DB_PATH):
            logger.warning(
                f"GeoIP ASN database not found at {ASN_DB_PATH}. ASN lookups will be disabled."
            )
        else:
            try:
                self.asn_reader = geoip2.database.Reader(ASN_DB_PATH)
                logger.info("Successfully loaded MaxMind GeoLite2-ASN database.")
            except Exception as e:
                logger.error(f"Failed to load GeoIP ASN database: {e}")

    def get_country_code(self, ip_address: str) -> str:
        """
        Returns the ISO 3166-1 alpha-2 country code (e.g., 'US', 'CN', 'BR') for the given IP.
        Returns empty string if lookup fails or DB is unavailable.
        """
        if not ip_address:
            return ""

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return "Internal"
        except ValueError:
            pass

        if not self.reader:
            return ""

        try:
            response = self.reader.country(ip_address)
            return response.country.iso_code or ""
        except geoip2.errors.AddressNotFoundError:
            return ""
        except Exception as e:
            logger.debug(f"GeoIP country lookup failed for {ip_address}: {e}")
            return ""

    def get_asn_org(self, ip_address: str) -> str:
        """
        Returns the ASN and ISP/Organization name for the given IP.
        Returns 'Internal' for private/loopback, 'Unknown (ASN DB Missing)' if DB not loaded,
        or 'Unknown' if not found.
        """
        if not ip_address:
            return ""

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return "Internal"
        except ValueError:
            pass

        if not self.asn_reader:
            return "Unknown (ASN DB Missing)"

        try:
            response = self.asn_reader.asn(ip_address)
            asn_num = response.autonomous_system_number
            asn_org = response.autonomous_system_organization
            if asn_num and asn_org:
                return f"AS{asn_num} {asn_org}"
            elif asn_num:
                return f"AS{asn_num}"
            return "Unknown"
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception as e:
            logger.debug(f"GeoIP ASN lookup failed for {ip_address}: {e}")
            return "Unknown"

    def __del__(self):
        if self.reader:
            try:
                self.reader.close()
            except Exception:
                pass
        if self.asn_reader:
            try:
                self.asn_reader.close()
            except Exception:
                pass


# Singleton instance
geoip_manager = GeoIPManager()
