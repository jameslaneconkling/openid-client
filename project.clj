(defproject openid-client "0.1.0-SNAPSHOT"
  :description "OpenID Connect authentication reference implementation"
  :url "https://github.com/jameslaneconkling/openid-client"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [ring/ring-core "1.6.3"]
                 [ring/ring-defaults "0.2.1"]
                 [ring-logger-timbre "0.7.6"]
                 [clj-http "3.8.0"]
                 [buddy/buddy-core "1.4.0"]
                 [buddy/buddy-sign "2.2.0"]
                 [environ "1.1.0"]]
  :profiles {:uberjar {:uberjar-exclusions [#"org/bouncycastle"]}}
  :ring {:handler openid-client.core/app}
  :plugins [[lein-ring "0.9.7"]
            [lein-environ "0.4.0"]]
  :target-path "target/%s")
