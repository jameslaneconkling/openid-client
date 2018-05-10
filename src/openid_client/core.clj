(ns openid-client.core
  (:require [ring.util.request :as req]
            [ring.util.response :as resp]
            [ring.util.codec :as codec]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults]]
            [ring.logger.timbre :refer [wrap-with-logger]]
            [clj-http.client :as client]
            [buddy.core.keys :as keys]
            [buddy.sign.jwt :as jwt]
            [clojure.string :as str]
            [environ.core :refer [env]])
  (:import [java.util UUID]
           [java.time Instant]))

(def config
  {:authorize-uri    "https://accounts.google.com/o/oauth2/v2/auth"
   :access-token-uri "https://www.googleapis.com/oauth2/v4/token"
   :user-info-uri    "https://www.googleapis.com/userinfo/v2/me" 
   :client-id        (env :client-id)
   :client-secret    (env :client-secret)
   :scopes           ["openid"] ;; profile email
   :redirect-uri     "/auth/google/callback"
   :success-uri      (env :success-uri)
   :error-uri        (env :error-uri)})

(defn validate-env
  [env-key]
  (if (nil? (env-key env))
    (throw (Exception. (str "Required environment variable '" env-key "' missing")))))

(run! validate-env
      [:client-id :client-secret :private-key :private-key-passphrase :public-key :success-uri :error-uri])

(def private-key (keys/private-key (env :private-key)
                                   (env :private-key-passphrase)))
(def public-key (keys/public-key (env :public-key)))

(defn redirect-uri
  [request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve (:redirect-uri config))
      str))

(defn authorize-uri
  [request]
  (str (:authorize-uri config)
       (if (.contains ^String (:authorize-uri config) "?") "&" "?")
       (codec/form-encode {:response_type "code"
                           :client_id     (:client-id config)
                           :redirect_uri  (redirect-uri request)
                           :prompt        "consent"
                           :state         (jwt/sign
                                           {:openid_user (get-in request [:cookies "openid_user" :value])
                                            :success_uri (get-in request [:params :success_uri])}
                                           private-key
                                           {:alg :rs256})
                           :scope         (str/join " " (:scopes config))})))

(defn success-uri
  [oauth-state user-id]
  (str (or (:success_uri oauth-state) (:success-uri config))
       "#"
       (codec/form-encode {:token (sign-jwt user-id)})))

(defn request-access-token
  [request]
  (-> (client/post (:access-token-uri config)
                   {:accept :json,
                    :as :json,
                    :form-params {:code (get-in request [:query-params "code"]) 
                                  :grant_type "authorization_code"
                                  :redirect_uri (redirect-uri request)
                                  :client_id (:client-id config)
                                  :client_secret (:client-secret config)}})
      :body
      :access_token))

(defn request-user-info 
  [access-token]
  (-> (client/get (:user-info-uri config)
                  {:oauth-token access-token,
                   :as :json})
      :body))

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
  [id]
  (jwt/sign {:id id
             :exp (+ (.getEpochSecond (Instant/now)) 21600)} ;; 6 hours
            private-key
            {:alg :rs256}))

(defn create-handler
  [& handlers]
  (let [handler-map (reduce
                     (fn [handler-map [method uri handler]]
                       (assoc-in handler-map [uri method] handler))
                     {}
                     handlers)]
    (fn [{:keys [uri request-method] :as request}]
      (if (get-in handler-map [uri request-method])
        ((get-in handler-map [uri request-method]) request)
        (-> (resp/not-found "NOT FOUND")
            (resp/content-type "text/plain"))))))


(defn create-user-id-cookie
  []
  {"openid_user" {:value (UUID/randomUUID)
                  :http-only true
                  ;; :secure true
                  :max-age 60 ;; 1 min
                  }})

(def handler (create-handler
              [:get "/auth"
               (fn [_]
                 (-> "/auth/index.html"
                     (resp/resource-response {:root "public"})
                     (resp/content-type "text/html")
                     (assoc :cookies (create-user-id-cookie))))]
              [:get "/auth/error"
               (fn [request]
                 (-> "/auth/error/index.html"
                     (resp/resource-response  {:root "public"})
                     (resp/content-type  "text/html")))]
              [:get "/auth/success"
               (fn [{:keys [cookies]}]
                 (-> "/auth/success/index.html"
                     (resp/resource-response  {:root "public"})
                     (resp/content-type  "text/html")))]
              [:get "/auth/google"
               (fn [request]
                 (resp/redirect (authorize-uri request)))]
              [:get "/auth/google/callback"
               (fn [request]
                 (try (let [openid_user (get-in request [:cookies "openid_user" :value])
                            oauth-state (-> request
                                            (get-in [:params :state])
                                            (jwt/unsign public-key {:alg :rs256}))]
                        (verify-state openid_user oauth-state)
                        (let [access-token (request-access-token request)
                              {:keys [id]} (request-user-info access-token)]
                          (verify-user id)
                          (resp/redirect (success-uri oauth-state id))))
                      (catch Exception _ (resp/redirect (:error-uri config)))))]))

(def app
  (-> handler
      (wrap-defaults (-> site-defaults
                         (assoc :session false)))
      wrap-with-logger))
