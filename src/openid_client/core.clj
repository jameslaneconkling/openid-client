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
  (:import [java.time Instant]))

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


(def private-key (keys/private-key (env :private-key)
                                   (env :private-key-passphrase)))

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
                           :scope         (str/join " " (:scopes config))})))

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

(defn sign-jwt
  [id]
  (jwt/sign {:id id
             :exp (+ (.getEpochSecond (Instant/now)) (* 60 60 6))} ;; 6 hours
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


(def handler (create-handler
              [:get "/auth" (fn [_] (-> "/auth/index.html"
                                        (resp/resource-response {:root "public"})
                                        (resp/content-type "text/html")))]
              [:get "/auth/error" (fn [_] (-> "/auth/error/index.html"
                                              (resp/resource-response  {:root "public"})
                                              (resp/content-type  "text/html")))]
              [:get "/auth/success" (fn [_] (-> "/auth/success/index.html"
                                                (resp/resource-response  {:root "public"})
                                                (resp/content-type  "text/html")))]
              [:get "/auth/google" (fn [request] (resp/redirect (authorize-uri request)))]
              [:get "/auth/google/callback" (fn [request] (try (let [access-token (request-access-token request)
                                                                     {:keys [id]} (request-user-info access-token)]
                                                                 (verify-user id)
                                                                 (resp/redirect (str (:success-uri config)
                                                                                     "?"
                                                                                     (codec/form-encode {:token (sign-jwt id)}))))
                                                               (catch Exception _ (resp/redirect (:error-uri config)))))]))

(def app
  (-> handler
      (wrap-defaults (-> site-defaults
                         (assoc :cookies false)
                         (assoc-in [:security :anti-forgery] false) ;; TODO - enable for select routes?
                         (assoc :session false))) ;; TODO - add secure-site-defaults
      wrap-with-logger))

;; (def request {:ssl-client-cert nil
;;               :remote-addr "0:0:0:0:0:0:0:1"
;;               :headers {"host" "localhost:3000"
;;                         "accept" "text/html"}
;;               :server-port 3000
;;               :content-length nil
;;               :content-type nil
;;               :character-encoding nil
;;               :uri "/auth"
;;               ;; :uri "/auth/google/callback"
;;               :server-name "localhost"
;;               :query-string "redirect=http%3A%2F%2Fcanvas.com&token=that"
;;               :scheme :http
;;               :request-method :get})
