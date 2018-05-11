(ns openid-client.utils
  (:require [ring.util.request :as req]
            [buddy.sign.jwt :as jwt]
            [ring.util.codec :as codec])
  (:import [java.net URI]
           [java.util UUID]
           [java.time Instant]))

(defn get-origin
  [uri-string]
  (let [uri (URI. uri-string)]
    (str
     (.getScheme uri)
     "://"
     (.getHost uri)
     (let [port (.getPort uri)]
       (if (= port -1)
         ""
         (str ":" port))))))

(defn validate-success-uri
  [uri valid-success-origins]
  (if-not (or (nil? uri)
              (contains? valid-success-origins (get-origin uri)))
    (throw (Exception. "400"))))

(defn verify-user
  [id]
  "Verify user with id exists in the system and optionally retrieve user info"
  (Thread/sleep 500)
  (if (not= id "113766572582938032472")
    (throw (Exception. "400"))))

(defn verify-state
  [openid_user oauth-state]
  "Verify oauth-state param matches user id from cookie assigned when user started signin at /auth"
  (if (not= openid_user (:openid_user oauth-state))
    (throw (Exception. "400"))))

(defn sign-jwt
  [id private-key]
  (jwt/sign {:id id
             :exp (+ (.getEpochSecond (Instant/now)) 21600)} ;; 6 hours
            private-key
            {:alg :rs256}))

(defn success-uri
  [oauth-state user-id default-success-uri private-key]
  (str (or (:success_uri oauth-state) default-success-uri)
       "#"
       (codec/form-encode {:token (sign-jwt user-id private-key)})))

(defn create-user-id-cookie
  []
  {"openid_user" {:value (UUID/randomUUID)
                  :http-only true
                  ;; :secure true
                  :max-age 60 ;; 1 min
                  }})
