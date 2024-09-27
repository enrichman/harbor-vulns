use std::iter::Map;
use serde::{Deserialize, Serialize};
use crate::MyError;

pub struct Client {
    host: String,
    username: String,
    password: String,
    client: reqwest::Client,
}


#[derive(Debug, Deserialize, Serialize)]
pub enum GoharborResponse {
    Error,
    Empty {},
    #[serde(rename(
        deserialize = "application/vnd.security.vulnerability.report; version=1.1",
        serialize = "application/vnd.security.vulnerability.report; version=1.1",
    ))]
    Vulnerabilities(Report),
}

#[derive(Debug, Deserialize, Serialize)]
struct GoharborError {
    code: String,
    message: String,
}

// https://github.com/goharbor/harbor/blob/cb7fef1840096162d51ed4297286027a33d7b5b1/src/pkg/scan/vuln/report.go#L208
#[derive(Debug, Deserialize, Serialize)]
pub struct Report {
    generated_at: String,
    scanner: Scanner,
    severity: Severity,
    vulnerabilities: Vec<VulnerabilityItem>,
    sbom: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Scanner {
    name: String,
    vendor: String,
    version: String,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum Severity {
    // None - only used to mark the overall severity of the scanned artifacts,
    // means no vulnerabilities attached with the artifacts,
    // (might be bypassed by the CVE allowlist).
    None,
    // Unknown - either a security problem that has not been assigned to a priority yet or
    // a priority that the scanner did not recognize.
    Unknown,
    // Negligible - technically a security problem, but is only theoretical in nature, requires
    // a very special situation, has almost no install base, or does no real damage.
    Negligible,
    // Low - a security problem, but is hard to exploit due to environment, requires a
    // user-assisted attack, a small install base, or does very little damage.
    Low,
    // Medium - a real security problem, and is exploitable for many people. Includes network
    // daemon denial of service attacks, cross-site scripting, and gaining user privileges.
    Medium,
    // High - a real problem, exploitable for many people in a default installation. Includes
    // serious remote denial of service, local root privilege escalations, or data loss.
    High,
    // Critical - a world-burning problem, exploitable for nearly all people in a default installation.
    // Includes remote root privilege escalations, or massive data loss.
    Critical,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VulnerabilityItem {
    // The unique identifier of the vulnerability.
    // e.g: CVE-2017-8283
    id: String,
    // An operating system or software dependency package containing the vulnerability.
    // e.g: dpkg
    package: String,
    // The version of the package containing the vulnerability.
    // e.g: 1.17.27
    version: String,
    // The version of the package containing the fix if available.
    // e.g: 1.18.0
    fix_version: String,
    // A standard scale for measuring the severity of a vulnerability.
    severity: Severity,
    // example: dpkg-source in dpkg 1.3.0 through 1.18.23 is able to use a non-GNU patch program
    // and does not offer a protection mechanism for blank-indented diff hunks, which allows remote
    // attackers to conduct directory traversal attacks via a crafted Debian source package, as
    // demonstrated by using of dpkg-source on NetBSD.
    description: String,
    // The list of link to the upstream database with the full description of the vulnerability.
    // Format: URI
    // e.g: List [ "https://security-tracker.debian.org/tracker/CVE-2017-8283" ]
    links: Vec<String>,
    // The artifact digests which the vulnerability belonged
    // e.g: sha256@ee1d00c5250b5a886b09be2d5f9506add35dfb557f1ef37a7e4b8f0138f32956
    artifact_digests: Vec<String>,
    // The CVSS3 and CVSS2 based scores and attack vector for the vulnerability item
    preferred_cvss: CVSS,
    // A separated list of CWE Ids associated with this vulnerability
    // e.g. CWE-465,CWE-124
    cwe_ids: Vec<String>,
    // A collection of vendor specific attributes for the vulnerability item
    // with each attribute represented as a key-value pair.
    vendor_attributes: serde_json::Map<String, serde_json::Value>,
}

// CVSS holds the score and attack vector for the vulnerability based on the CVSS3 and CVSS2 standards

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CVSS {
    // The CVSS-3 score for the vulnerability
    // e.g. 2.5
    score_v3: Option<f64>,
    // The CVSS-3 score for the vulnerability
    // e.g. 2.5
    score_v2: Option<f64>,
    // The CVSS-3 attack vector.
    // e.g. CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
    vector_v3: String,
    // The CVSS-3 attack vector.
    // e.g. AV:L/AC:M/Au:N/C:P/I:N/A:N
    vector_v2: String,
}


impl Client {
    pub(crate) fn new(host: &str, username: &str, password: &str) -> Result<Self, MyError> {
        Ok(Self {
            host: host.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
            client: reqwest::Client::builder().build()?,
        })
    }

    pub(crate) fn build_endpoint(&self, path: &str) -> String {
        format!("{}{}{}", self.host, "/api/v2.0", path)
    }

    // https://github.com/goharbor/harbor/blob/main/api/v2.0/swagger.yaml#L1416-L1447
    pub(crate) async fn vulnerabilities(&self, project_name: &str, repository_name: &str, reference: &str) -> Result<GoharborResponse, MyError> {
        // /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/vulnerabilities:
        let path = format!("/projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/vulnerabilities");
        let endpoint = self.build_endpoint(path.as_str());

        let body = self.client.get(endpoint)
            .basic_auth(self.username.as_str(), Some(self.password.as_str()))
            .send()
            .await?
            .text()
            .await?;

        Ok(serde_json::from_str::<GoharborResponse>(body.as_str())?)
    }
}

//curl -u 'harbor - demo-account:Password123' https://demo.goharbor.io/api/v2.0/projects/test-proj-demo/repositories/nginx/artifacts/latest/additions/vulnerabilities

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_response() {
        let res = serde_json::from_str::<GoharborResponse>("{}").unwrap();
        match res {
            GoharborResponse::Empty {} => {
                panic!("bum")
            }
            _ => panic!("unexpected result")
        }
    }

    #[test]
    fn vuln_response() {
        let body = r#"{
  "application/vnd.security.vulnerability.report; version=1.1": {
    "generated_at": "2024-08-01T09:37:05.561615505Z",
    "scanner": {
      "name": "Trivy",
      "vendor": "Aqua Security",
      "version": "v0.51.2"
    },
    "severity": "Critical",
    "vulnerabilities": [
      {
        "id": "CVE-2024-5171",
        "package": "libaom3",
        "version": "3.6.0-1",
        "fix_version": "",
        "severity": "Critical",
        "description": "Integer overflow in libaom internal function img_alloc_helper can lead to heap buffer overflow. This function can be reached via 3 callers:\n\n\n  *  Calling aom_img_alloc() with a large value of the d_w, d_h, or align parameter may result in integer overflows in the calculations of buffer sizes and offsets and some fields of the returned aom_image_t struct may be invalid.\n  *  Calling aom_img_wrap() with a large value of the d_w, d_h, or align parameter may result in integer overflows in the calculations of buffer sizes and offsets and some fields of the returned aom_image_t struct may be invalid.\n  *  Calling aom_img_alloc_with_border() with a large value of the d_w, d_h, align, size_align, or border parameter may result in integer overflows in the calculations of buffer sizes and offsets and some fields of the returned aom_image_t struct may be invalid.",
        "links": [
          "https://avd.aquasec.com/nvd/cve-2024-5171"
        ],
        "artifact_digests": [
          "sha256:4ac65f23061de2faef157760fa2125c954b5b064bc25e10655e90bd92bc3b354"
        ],
        "preferred_cvss": {
          "score_v3": 9.8,
          "score_v2": null,
          "vector_v3": "",
          "vector_v2": ""
        },
        "cwe_ids": [
          "CWE-190",
          "CWE-20"
        ],
        "vendor_attributes": {
          "CVSS": {
            "nvd": {
              "V3Score": 9.8,
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            "redhat": {
              "V3Score": 7,
              "V3Vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
            }
          }
        }
      }
    ]
  }
}"#;
        let res = serde_json::from_str::<GoharborResponse>(body).unwrap();
        println!("XXX {:?}", res);

        match res {
            GoharborResponse::Vulnerabilities(report) => {
                assert_eq!(report.generated_at, "2024-08-01T09:37:05.561615505Z".to_string());
                assert_eq!(report.scanner, Scanner {
                    name: "Trivy".to_string(),
                    vendor: "Aqua Security".to_string(),
                    version: "v0.51.2".to_string(),
                });
                assert_eq!(report.severity, Severity::Critical);
            }
            _ => panic!("unexpected response")
        }
    }

    #[test]
    fn vuln_response2() {
        let res = serde_json::to_string(&GoharborResponse::Vulnerabilities(Report {
            generated_at: "123".to_string(),
            severity: Severity::Critical,
            scanner: Scanner {
                name: "".to_string(),
                vendor: "".to_string(),
                version: "".to_string(),
            },
            vulnerabilities: vec![],
            sbom: None,
        })).unwrap();
        println!("XXX {:?}", res);
    }
}