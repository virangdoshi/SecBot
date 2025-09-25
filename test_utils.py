import pytest
import responses
import json
from unittest.mock import patch, MagicMock
from utils import cve_search, package_cve_search


class TestCVESearch:
    """Test cases for CVE search functionality."""
    
    def setup_method(self):
        """Set up test configuration."""
        self.config = {
            "request_timeout": 10,
            "max_cve_results": 5
        }
    
    @responses.activate
    def test_cve_search_success(self):
        """Test successful CVE search."""
        # Mock NIST API response
        mock_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "cisaVulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                    "descriptions": [{
                        "value": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration..."
                    }],
                    "references": [{
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                    }]
                }
            }]
        }
        
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
            json=mock_response,
            status=200
        )
        
        result = cve_search(self.config, "CVE-2021-44228")
        
        assert "Apache Log4j2 Remote Code Execution Vulnerability" in result
        assert "Apache Log4j2 2.0-beta9 through 2.15.0" in result
        assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in result
    
    def test_cve_search_invalid_format(self):
        """Test CVE search with invalid format."""
        result = cve_search(self.config, "INVALID-FORMAT")
        assert "Invalid CVE format" in result
        assert "CVE-2021-44228" in result
    
    @responses.activate
    def test_cve_search_not_found(self):
        """Test CVE search when CVE is not found."""
        mock_response = {"vulnerabilities": []}
        
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-9999-99999",
            json=mock_response,
            status=200
        )
        
        result = cve_search(self.config, "CVE-9999-99999")
        assert "No vulnerability found for CVE-9999-99999" in result
    
    @responses.activate
    def test_cve_search_request_exception(self):
        """Test CVE search with request exception."""
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
            status=500
        )
        
        result = cve_search(self.config, "CVE-2021-44228")
        assert "Sorry, there was an error fetching CVE information" in result
    
    @responses.activate
    def test_cve_search_missing_description(self):
        """Test CVE search with missing description."""
        mock_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [],
                    "references": []
                }
            }]
        }
        
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
            json=mock_response,
            status=200
        )
        
        result = cve_search(self.config, "CVE-2021-44228")
        assert "No description available" in result
        assert "No references available" in result


class TestPackageCVESearch:
    """Test cases for package CVE search functionality."""
    
    def setup_method(self):
        """Set up test configuration."""
        self.config = {
            "request_timeout": 10,
            "max_cve_results": 2
        }
    
    @responses.activate
    def test_package_cve_search_success(self):
        """Test successful package CVE search."""
        mock_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{
                            "value": "Apache Log4j2 vulnerability description"
                        }]
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2021-45046",
                        "descriptions": [{
                            "value": "Another Log4j vulnerability"
                        }]
                    }
                }
            ]
        }
        
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=log4j",
            json=mock_response,
            status=200
        )
        
        result = package_cve_search(self.config, "log4j")
        
        assert "CVE-2021-44228" in result
        assert "CVE-2021-45046" in result
        assert "Apache Log4j2 vulnerability description" in result
        assert "Another Log4j vulnerability" in result
    
    def test_package_cve_search_empty_package(self):
        """Test package CVE search with empty package name."""
        result = package_cve_search(self.config, "")
        assert "Please provide a valid package name" in result
        
        result = package_cve_search(self.config, "   ")
        assert "Please provide a valid package name" in result
    
    @responses.activate
    def test_package_cve_search_no_results(self):
        """Test package CVE search with no results."""
        mock_response = {"vulnerabilities": []}
        
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nonexistentpackage",
            json=mock_response,
            status=200
        )
        
        result = package_cve_search(self.config, "nonexistentpackage")
        assert "No vulnerabilities found for package 'nonexistentpackage'" in result
    
    @responses.activate
    def test_package_cve_search_max_results_exceeded(self):
        """Test package CVE search with results exceeding max limit."""
        # Create more vulnerabilities than max_cve_results
        vulnerabilities = []
        for i in range(5):  # More than max_cve_results (2)
            vulnerabilities.append({
                "cve": {
                    "id": f"CVE-2021-{i:05d}",
                    "descriptions": [{
                        "value": f"Vulnerability {i} description"
                    }]
                }
            })
        
        mock_response = {"vulnerabilities": vulnerabilities}
        
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=testpackage",
            json=mock_response,
            status=200
        )
        
        result = package_cve_search(self.config, "testpackage")
        
        # Should only show first 2 results
        assert "CVE-2021-00000" in result
        assert "CVE-2021-00001" in result
        assert "CVE-2021-00002" not in result
        assert "and 3 more results" in result
    
    @responses.activate
    def test_package_cve_search_request_exception(self):
        """Test package CVE search with request exception."""
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=testpackage",
            status=500
        )
        
        result = package_cve_search(self.config, "testpackage")
        assert "Sorry, there was an error fetching CVE information" in result
    
    @responses.activate
    def test_package_cve_search_missing_description(self):
        """Test package CVE search with missing description."""
        mock_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": []
                }
            }]
        }
        
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=testpackage",
            json=mock_response,
            status=200
        )
        
        result = package_cve_search(self.config, "testpackage")
        assert "CVE-2021-44228" in result
        assert "No description available" in result


if __name__ == "__main__":
    pytest.main([__file__])
