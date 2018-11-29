# jira-httpheader-auth

HTTP Headers authentication plugin.

## Summary
Will allow authenticated access to JIRA for http requests with the following (hardcoded) header:
* `X-Forwarded-Login` (the username of a valid JIRA user)

This might be useful when JIRA instances are hosted behind a reverse-proxy which is responsible for authentication.

## Installation

* Deploy httpheader-<version>.jar to `${jira_base}/atlassian-jira/WEB-INF/lib`
* Use `<authenticator class="com.redgate.jira.auth.httpheader.HttpHeaderAuthenticator"/>` in `${jira_base}/atlassian-jira/WEB-INF/classes/seraph-config.xml`

## Development

### Prerequisites

* JDK 1.8
* Maven
* Atlassian SDK (to start a local jira instance)

### Build & Test

The .jar file can be build by `mvn package`. The .jar file will be available in `target/`

```
# How to quickly start a local jira instance.
atlas-run-standalone --product jira --version 7.12.0
# local jira instance is available at http://localhost:2990/jira/

# build the jar file
mvn package
# deploy it to the local jira instance
cp ./target/httpheader-1.0.0-SNAPSHOT.jar ./amps-standalone-jira-7.12.0/target/jira/webapp/WEB-INF/lib/

# update seraph-config to use our custom authenticator
# in amps-standalone-jira-7.12.0/target/jira/webapp/WEB-INF/classes/seraph-config.xml
# set <authenticator class="com.redgate.jira.auth.httpheader.HttpHeaderAuthenticator"/>

# restart jira
```

## Release a new version

* Update `<version>` in `pom.xml`
* `mvn package`
* Create tag and upload jar to https://github.com/red-gate/jira-httpheader-auth/releases
