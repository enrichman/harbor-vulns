use serde::{Deserialize, Serialize};
use crate::MyError;

pub struct Client {
    host: String,
    username: String,
    password: String,
    client: reqwest::Client,
}


#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum GoharborResponse {
    Error,
    Empty {},
    #[serde(rename(
        deserialize = "application/vnd.security.vulnerability.report; version=1.1",
        serialize = "application/vnd.security.vulnerability.report; version=1.1",
    ))]
    Report(Report),
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct GoharborError {
    code: String,
    message: String,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Report {
    generated_at: String,
    severity: Severity,
    scanner: Scanner,
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


#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Scanner {
    name: String,
    vendor: String,
    version: String,
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
        assert_eq!(res, GoharborResponse::Empty {});
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
            GoharborResponse::Error => {
                println!("XXX {:?}", res);
            }
            GoharborResponse::Report(report) => {
                println!("XXX {:?}", report);
            }
            _ => {}
        }

        // assert_eq!(res, GoharborResponse::GoharborSuccess(VulnReport{generated_at:"2024-08-01T09:37:05.561615505Z".to_string()}));
    }

    #[test]
    fn vuln_response2() {
        let res = serde_json::to_string(&GoharborResponse::Report(Report {
            generated_at: "123".to_string(),
            severity: Severity::Critical,
            scanner: Scanner {
                name: "".to_string(),
                vendor: "".to_string(),
                version: "".to_string(),
            },
        })).unwrap();
        println!("XXX {:?}", res);
    }
}