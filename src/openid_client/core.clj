(ns openid-client.core
  (:require [openid-client.handler :refer [create-handler]]
            [openid-client.utils :refer [get-origin
                                         validate-success-uri
                                         verify-user
                                         verify-state
                                         create-user-id-cookie
                                         success-uri]]
            [ring.util.request :as req]
            [ring.util.response :as resp]
            [ring.util.codec :as codec]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults]]
            [ring.logger.timbre :refer [wrap-with-logger]]
            [clj-http.client :as client]
            [buddy.core.keys :as keys]
            [buddy.sign.jwt :as jwt]
            [clojure.string :as str]
            [environ.core :refer [env]])
  (:import [java.net URI]))

(defn validate-env
  [env-key]
  (if-not (env-key env)
    (throw (Exception. (str "Required environment variable '" env-key "' missing")))))

(defn validate-success-origins
  [origin]
  (if-not (re-matches #"https?:\/\/.*" origin)
    (throw (Exception. (str "Expected valid-success-origins to be a space-separated array of valid url origins.  Received invalid origin " origin)))))

(run! validate-env
      [:client-id :client-secret :private-key :private-key-passphrase
       :public-key :error-uri :default-success-uri])

(if (env :valid-success-origins)
  (run! validate-success-origins (str/split (env :valid-success-origins) #" ")))

(def config
  {:authorize-uri         "https://accounts.google.com/o/oauth2/v2/auth"
   :access-token-uri      "https://www.googleapis.com/oauth2/v4/token"
   :user-info-uri         "https://www.googleapis.com/userinfo/v2/me" 
   :client-id             (env :client-id)
   :client-secret         (env :client-secret)
   :scopes                ["openid"] ;; profile email
   :redirect-uri          "/auth/google/callback"
   :error-uri             (env :error-uri)
   :default-success-uri   (env :default-success-uri)
   :valid-success-origins (->> (str/split (env :valid-success-origins "") #" ")
                               (filter #(not= "" %))
                               (map get-origin)
                               (into #{}))})


(def private-key (keys/private-key (env :private-key)
                                   (env :private-key-passphrase)))
(def public-key (keys/public-key (env :public-key)))

(defn redirect-uri
  [request]
  (-> (req/request-url request)
      (URI/create)
      (.resolve (:redirect-uri config))
      str))

(defn authorize-uri
  [request]
  (let [success-uri (get-in request [:params :success_uri])]
    (validate-success-uri success-uri (:valid-success-origins config))
    (str (:authorize-uri config)
         (if (.contains ^String (:authorize-uri config) "?") "&" "?")
         (codec/form-encode {:response_type "code"
                             :client_id     (:client-id config)
                             :redirect_uri  (redirect-uri request)
                             :prompt        "consent"
                             :state         (jwt/sign
                                             {:openid_user (get-in request [:cookies "openid_user" :value])
                                              :success_uri success-uri}
                                             private-key
                                             {:alg :rs256})
                             :scope         (str/join " " (:scopes config))}))))

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

;; TODO - might be possible to get this along w/ the access-token, requiring one less request
(defn request-user-info 
  [access-token]
  (-> (client/get (:user-info-uri config)
                  {:oauth-token access-token,
                   :as :json})
      :body))

(def handler (create-handler
              config
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
                 (try
                   (resp/redirect (authorize-uri request))
                   (catch Exception _ (resp/redirect (:error-uri config)))))]
              [:get "/auth/google/callback"
               (fn [request]
                 (try
                   (let [openid_user (get-in request [:cookies "openid_user" :value])
                         oauth-state (-> request
                                         (get-in [:params :state])
                                         (jwt/unsign public-key {:alg :rs256}))]
                     (verify-state openid_user oauth-state)
                     (let [access-token (request-access-token request)
                           {:keys [id]} (request-user-info access-token)]
                       (verify-user id)
                       (resp/redirect
                        (success-uri oauth-state id (:default-success-uri config) private-key))))
                   (catch Exception _ (resp/redirect (:error-uri config)))))]))

(def app
  (-> handler
      (wrap-defaults (-> site-defaults
                         (assoc :session false)))
      wrap-with-logger))
