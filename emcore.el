;;; emcore.el --- Client for the emcore ERP API  -*- lexical-binding: t; -*-

;; Author: Ori <okayihan@emotions.ch>
;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, comm

;;; Commentary:

;; Client for the erp.emotions.ch ColdBox REST API (/api/v2).
;;
;; The API has no machine authentication — this package replays the
;; browser login flow (email + password, then an emailed 6-digit MFA
;; token) and relies on url.el's persistent cookie store for the
;; JSESSIONID session cookie and the 30-day
;; `mfa-trusted-device-identifier' cookie (which skips MFA on
;; subsequent logins).  Credentials are looked up via auth-source
;; (machine erp.emotions.ch).
;;
;; An expired session does not yield a JSON 401 — the server redirects
;; to the HTML login page.  `emcore-request' detects the non-JSON
;; response, re-runs the login flow and retries once.
;;
;; Ticket comments/history have no API endpoint at all; they are
;; scraped from the server-rendered ticket page
;; (/service-desk/ticketing/ticket?ticketNo=N).
;;
;; See emcore-org.el for org-mode dynamic blocks and org-clock
;; integration.

;;; Code:

(require 'cl-lib)
(require 'seq)
(require 'url)
(require 'url-http)
(require 'json)
(require 'auth-source)
(require 'dom)

(defvar url-http-response-status)
(defvar url-http-end-of-headers)

(defgroup emcore nil
  "Client for the emcore ERP API."
  :group 'tools
  :prefix "emcore-")

(defcustom emcore-base-url "https://erp.emotions.ch"
  "Base URL of the emcore ERP instance, without trailing slash."
  :type '(choice (const :tag "Production" "https://erp.emotions.ch")
                 (const :tag "Testing" "https://erp.test.emotions.ch")
                 (const :tag "Development" "https://erp.devlocal.emotions.ch")
                 (string :tag "Other")))

(defcustom emcore-timezone "Europe/Zurich"
  "IANA timezone passed to TRS analysis endpoints."
  :type 'string)

(defcustom emcore-save-device t
  "When non-nil, request a trusted-device cookie on MFA login.
The cookie is valid for 30 days and skips the MFA step on later logins."
  :type 'boolean)

(define-error 'emcore-error "emcore error")
(define-error 'emcore-api-error "emcore API error" 'emcore-error)
(define-error 'emcore-auth-error "emcore authentication error" 'emcore-error)

;;;; HTTP layer

(defun emcore--fetch (method path &optional data content-type)
  "Perform METHOD request against PATH on `emcore-base-url'.
DATA is a raw request body string, sent with CONTENT-TYPE.
Redirects are followed; returns a plist (:status N :body STRING) of
the final response."
  (let* ((url-request-method method)
         (url-request-data (and data (encode-coding-string data 'utf-8)))
         (url-request-extra-headers
          (append (and data `(("Content-Type" . ,content-type)))
                  '(("Accept" . "application/json, text/html"))))
         (buf (url-retrieve-synchronously (concat emcore-base-url path) t nil 30)))
    (unless buf
      (signal 'emcore-error (list (format "No response from %s" emcore-base-url))))
    (with-current-buffer buf
      (unwind-protect
          (list :status url-http-response-status
                :body (decode-coding-string
                       (buffer-substring-no-properties
                        (if (markerp url-http-end-of-headers)
                            (min (1+ url-http-end-of-headers) (point-max))
                          (point-min))
                        (point-max))
                       'utf-8))
        (kill-buffer buf)))))

(defun emcore--path (path &optional params)
  "Append PARAMS (an alist, nil values dropped) to PATH as a query string."
  (let ((params (seq-filter #'cdr params)))
    (concat path
            (when params
              (concat "?" (mapconcat
                           (lambda (kv)
                             (concat (url-hexify-string (format "%s" (car kv)))
                                     "="
                                     (url-hexify-string (format "%s" (cdr kv)))))
                           params "&"))))))

(defun emcore--json-body-p (resp)
  (let ((body (string-trim-left (or (plist-get resp :body) ""))))
    (and (not (string-empty-p body))
         (memq (aref body 0) '(?\{ ?\[)))))

(cl-defun emcore-request (method path &key params body (retry t))
  "Call API endpoint PATH (relative to /api/v2) and return its `data' field.
PARAMS is a query-string alist, BODY an alist sent as JSON.  A
non-JSON response means the session expired: the login flow is run and
the request retried once (unless RETRY is nil).  An `error: true'
envelope signals `emcore-api-error' with (MESSAGE CODE DATA)."
  (let ((resp (emcore--fetch method
                             (emcore--path (concat "/api/v2" path) params)
                             (and body (json-serialize body))
                             "application/json")))
    (if (not (emcore--json-body-p resp))
        (if retry
            (progn
              (emcore-login)
              (emcore-request method path :params params :body body :retry nil))
          (signal 'emcore-auth-error
                  (list "Not authenticated (got non-JSON response)")))
      (let* ((json (json-parse-string (plist-get resp :body)
                                      :object-type 'alist :array-type 'list
                                      :null-object nil :false-object nil))
             (data (alist-get 'data json)))
        (if (alist-get 'error json)
            (signal 'emcore-api-error
                    (list (or (car (alist-get 'messages json)) "API error")
                          (alist-get 'error data)
                          data))
          data)))))

(defun emcore-api-error-code (err)
  "Return the stable `data.error' code of an `emcore-api-error' ERR."
  (nth 2 err))

;;;; Authentication

(defun emcore--credentials ()
  "Return (EMAIL . PASSWORD), from auth-source or by prompting."
  (let* ((host (url-host (url-generic-parse-url emcore-base-url)))
         (auth (car (auth-source-search :host host :max 1 :require '(:user :secret)))))
    (if auth
        (cons (plist-get auth :user) (auth-info-password auth))
      (cons (read-string (format "emcore email (%s): " host))
            (read-passwd "emcore password: ")))))

(defun emcore--form-encode (fields)
  (mapconcat (lambda (kv)
               (concat (url-hexify-string (car kv)) "="
                       (url-hexify-string (cdr kv))))
             fields "&"))

;;;###autoload
(defun emcore-login ()
  "Log in to the ERP, handling the email-MFA step.
With a valid trusted-device cookie the MFA step is skipped by the
server.  Never retries credentials: the account blocks after 5 failed
attempts."
  (interactive)
  (pcase-let* ((`(,user . ,pass) (emcore--credentials))
               (resp (emcore--fetch
                      "POST" "/auth/main/index"
                      (emcore--form-encode `(("username" . ,user)
                                             ("password" . ,pass)))
                      "application/x-www-form-urlencoded"))
               (body (plist-get resp :body)))
    (cond
     ((string-match-p "name=\"mfaToken\"" body)
      (emcore--mfa body))
     ((string-match-p "name=\"password\"" body)
      (signal 'emcore-auth-error
              (list "Login failed — check credentials (account blocks after 5 attempts)")))
     (t (message "emcore: logged in (trusted device)")))))

(defun emcore--mfa (mfa-page)
  "Submit the MFA token.  MFA-PAGE is the rendered MFA form HTML.
In development/testing the server pre-fills the token into the form;
it is scraped and submitted automatically."
  (let* ((prefilled (and (string-match
                          "id=\"mfaToken\"[^>]*value=\"\\([0-9]\\{6\\}\\)\"" mfa-page)
                         (match-string 1 mfa-page)))
         (token (or prefilled
                    (read-string "emcore MFA token (check your email): ")))
         (resp (emcore--fetch
                "POST" "/auth/main/mfa"
                (emcore--form-encode
                 `(("mfaToken" . ,token)
                   ,@(when emcore-save-device '(("saveDevice" . "on")))))
                "application/x-www-form-urlencoded"))
         (body (plist-get resp :body)))
    (if (string-match-p "name=\"password\"\\|name=\"mfaToken\"" body)
        (signal 'emcore-auth-error (list "MFA failed — wrong or expired token"))
      (message "emcore: logged in"))))

;;;; Time formatting

(defun emcore--utc-minute (time)
  "Format TIME as the TRS \"yyyy-MM-ddTHH:mm\" UTC string (no Z, no seconds)."
  (format-time-string "%Y-%m-%dT%H:%M" time t))

(defun emcore--utc-iso (time)
  "Format TIME as a full UTC ISO string for the analysis endpoints."
  (format-time-string "%Y-%m-%dT%H:%M:%S.000Z" time t))

(defun emcore-format-minutes (minutes)
  "Render MINUTES as H:MM (negative-safe)."
  (let ((m (round minutes)))
    (format "%s%d:%02d" (if (< m 0) "-" "") (/ (abs m) 60) (mod (abs m) 60))))

(defun emcore--date-to-time (date &optional day-offset)
  "Local midnight of DATE (a \"YYYY-MM-DD\" string), plus DAY-OFFSET days."
  (pcase-let ((`(_ _ _ ,d ,m ,y . _) (parse-time-string date)))
    (encode-time (list 0 0 0 (+ d (or day-offset 0)) m y nil -1 nil))))

;;;; Case-insensitive field access
;; GET /tickets/:id/edit builds its struct from a DB query row; key
;; casing depends on the CFML engine, so look fields up loosely.

(defun emcore-get (alist key)
  "Get KEY (a symbol) from ALIST, falling back to case-insensitive match."
  (or (alist-get key alist)
      (cdr (assoc-string (symbol-name key) alist t))))

;;;; Tickets

(defun emcore-tickets (&optional q limit firm-id)
  "Search tickets.  Returns a list of (ticketId ticketNo title) alists.
An empty Q returns the most recent LIMIT (default 50, max 200)."
  (alist-get 'tickets
             (emcore-request "GET" "/tickets"
                             :params `(("q" . ,(or q ""))
                                       ("limit" . ,(or limit 50))
                                       ("firmId" . ,firm-id)))))

(defun emcore-ticket (ticket-id)
  "Full ticket data for TICKET-ID (35-char UUID).
Includes `ticketStatusCode' (e.g. IN_PROGRESS), `priority'
\(urgent/high/medium/low), names for assignee/firm/project, dates and
effort fields."
  (emcore-request "GET" (format "/tickets/%s/edit" ticket-id)))

(defun emcore-ticket-update (ticket-id fields)
  "Quick-edit TICKET-ID.  FIELDS is an alist over the allowed subset:
assignedUserId ticketStatusId hidden priority orderNo startDate
endDate percentageComplete.  Returns the recorded changes."
  (emcore-request "PUT" (format "/tickets/%s/edit" ticket-id) :body fields))

(defun emcore-ticket-id (ticket-no)
  "Resolve human ticket number TICKET-NO to its ticketId UUID."
  (let* ((no (format "%s" ticket-no))
         (hit (seq-find (lambda (tk)
                          (equal (format "%s" (alist-get 'ticketNo tk)) no))
                        (emcore-tickets no))))
    (or (alist-get 'ticketId hit)
        (signal 'emcore-error (list (format "Ticket #%s not found" no))))))

(defun emcore-read-ticket ()
  "Prompt for a ticket with completion; return its alist.
Accepts a plain ticket number as free-form input."
  (let* ((tickets (emcore-tickets "" 200))
         (cands (mapcar (lambda (tk)
                          (cons (format "#%s %s"
                                        (alist-get 'ticketNo tk)
                                        (alist-get 'title tk))
                                tk))
                        tickets))
         (input (completing-read "Ticket: " cands))
         (hit (cdr (assoc input cands))))
    (cond (hit hit)
          ((string-match "\\`#?\\([0-9]+\\)\\'" input)
           (let ((no (match-string 1 input)))
             `((ticketId . ,(emcore-ticket-id no)) (ticketNo . ,no))))
          (t (user-error "No ticket selected")))))

;;;; Ticket history (scraped — no API endpoint exists)

(defun emcore--fetch-html (path)
  "GET an MVC page, re-logging in once if the login page comes back."
  (let ((body (plist-get (emcore--fetch "GET" path) :body)))
    (when (string-match-p "name=\"password\"" body)
      (emcore-login)
      (setq body (plist-get (emcore--fetch "GET" path) :body)))
    (with-temp-buffer
      (insert body)
      (libxml-parse-html-region (point-min) (point-max)))))

(defun emcore--history-entry (node)
  "Parse one div.ticket-history NODE into an alist."
  (let* ((author-node (car (dom-search
                            node (lambda (n) (dom-attr n 'data-user-card)))))
         (time-node (seq-find
                     (lambda (n) (and (not (dom-attr n 'data-user-card))
                                      (member "fw-semibold"
                                              (split-string (or (dom-attr n 'class) "")))))
                     (dom-by-tag node 'span)))
         (comment-node (car (dom-search
                             node (lambda (n)
                                    (string-prefix-p "history-comment-"
                                                     (or (dom-attr n 'id) ""))))))
         (changes (mapcar (lambda (li) (string-trim (dom-texts li " ")))
                          (and (car (dom-by-class node "list-primary"))
                               (dom-by-tag (car (dom-by-class node "list-primary")) 'li)))))
    `((source . ,(dom-attr node 'data-source))
      (id . ,(and comment-node
                  (string-remove-prefix "history-comment-"
                                        (dom-attr comment-node 'id))))
      (author . ,(and author-node (string-trim (dom-texts author-node))))
      (time . ,(and time-node (string-trim (dom-texts time-node))))
      (comment . ,comment-node)
      (changes . ,changes))))

(defun emcore-ticket-history (ticket-no)
  "Scrape the history/comments of ticket TICKET-NO from its ticket page.
Returns a list of alists with keys: source (\"tickethistories\" or
\"timetrackings\"), id (the history/tracking UUID), author, time
\(localized display string), comment (a DOM node or nil), changes
\(list of display strings)."
  (let ((dom (emcore--fetch-html
              (format "/service-desk/ticketing/ticket?ticketNo=%s" ticket-no))))
    (mapcar #'emcore--history-entry
            (seq-filter (lambda (n) (dom-attr n 'data-source))
                        (dom-by-class dom "ticket-history")))))

(defun emcore-ticket-comment-update (history-id comment)
  "Update own comment HISTORY-ID (owner-only) to COMMENT (HTML or text)."
  (emcore-request "PUT" (format "/ticket-history/%s/comment" history-id)
                  :body `((comment . ,comment))))

;;;; Users

(defun emcore-users (&optional q limit)
  "Search active users.  Returns (userId fullName email) alists."
  (alist-get 'users
             (emcore-request "GET" "/users/lookup"
                             :params `(("q" . ,(or q ""))
                                       ("limit" . ,(or limit 50))))))

;;;; TRS time tracking

(defun emcore-tracking-get (id &optional user-id)
  (emcore-request "GET" (format "/trs/time-trackings/%s" id)
                  :params `(("userId" . ,user-id))))

(defun emcore-tracking-create (type start &optional end comment ticket-id user-id)
  "Create a time-tracking entry; returns its data (`timeTrackingId').
TYPE is \"working-time\" or \"break\" (break requires END).  START/END
are Emacs time values; END nil leaves a working-time entry running."
  (emcore-request "POST" "/trs/time-trackings"
                  :body (seq-filter #'cdr
                                    `((type . ,type)
                                      (startUTC . ,(emcore--utc-minute start))
                                      (endUTC . ,(and end (emcore--utc-minute end)))
                                      (comment . ,comment)
                                      (ticketId . ,ticket-id)
                                      (userId . ,user-id)))))

(defun emcore-tracking-stop (id &optional end user-id)
  "Stop running entry ID at END (default: now)."
  (emcore-request "POST" (format "/trs/time-trackings/%s/stop" id)
                  :params `(("userId" . ,user-id))
                  :body `((endUTC . ,(emcore--utc-minute (or end (current-time)))))))

(defun emcore-tracking-set-comment (id comment)
  "Set COMMENT on entry ID.  Owner-only."
  (emcore-request "PUT" (format "/trs/time-trackings/%s/comment" id)
                  :body `((comment . ,comment))))

(defun emcore-tracking-delete (id &optional user-id)
  (emcore-request "DELETE" (format "/trs/time-trackings/%s" id)
                  :params `(("userId" . ,user-id))))

;;;; TRS analysis

(defun emcore-analysis (start end &optional user-id)
  "Summary for [START, END) (Emacs time values, END exclusive)."
  (emcore-request "GET" "/trs/analysis"
                  :params `(("start" . ,(emcore--utc-iso start))
                            ("end" . ,(emcore--utc-iso end))
                            ("timeZone" . ,emcore-timezone)
                            ("userId" . ,user-id))))

(defun emcore-analysis-days (start end &optional user-id)
  "Per-day breakdown for [START, END).  Each day carries its entries.
Note: break entries never appear here (server-side filter)."
  (emcore-request "GET" "/trs/analysis/days"
                  :params `(("start" . ,(emcore--utc-iso start))
                            ("end" . ,(emcore--utc-iso end))
                            ("timeZone" . ,emcore-timezone)
                            ("userId" . ,user-id))))

(defun emcore-active-tracking ()
  "Return the running time-tracking entry as an alist, or nil.
There is no list endpoint; the entry is recovered from the per-day
analysis of the last two days (its `timeTrackingId' key is what
matters)."
  (let* ((now (current-time))
         (days (alist-get 'days (emcore-analysis-days
                                 (time-subtract now (* 24 3600))
                                 (time-add now (* 24 3600)))))
         (entries (apply #'append
                         (mapcar (lambda (d) (alist-get 'entries d)) days))))
    (seq-find (lambda (e)
                (and (equal (alist-get 'source e) "timeTracking")
                     (alist-get 'isActive e)))
              entries)))

;;;; Interactive time tracking

(defvar emcore-active-tracking-id nil
  "The timeTrackingId started from this Emacs session, if any.")

(defun emcore-start-tracking (start &optional comment ticket-id)
  "Create a running working-time entry starting at START.
On ACTIVE_ENTRY_EXISTS, offer to stop the running entry and retry.
Returns the new timeTrackingId."
  (let ((create (lambda ()
                  (alist-get 'timeTrackingId
                             (emcore-tracking-create
                              "working-time" start nil comment ticket-id)))))
    (condition-case err
        (funcall create)
      (emcore-api-error
       (if (and (equal (emcore-api-error-code err) "ACTIVE_ENTRY_EXISTS")
                (y-or-n-p "emcore: an entry is already running — stop it and start the new one? "))
           (let ((active (emcore-active-tracking)))
             (when active
               (emcore-tracking-stop (alist-get 'timeTrackingId active)))
             (funcall create))
         (signal (car err) (cdr err)))))))

;;;###autoload
(defun emcore-clock-in ()
  "Start tracking working time on a ticket (standalone, without org)."
  (interactive)
  (let* ((ticket (emcore-read-ticket))
         (comment (read-string "Comment (optional): "))
         (id (emcore-start-tracking (current-time)
                                    (unless (string-empty-p comment) comment)
                                    (alist-get 'ticketId ticket))))
    (setq emcore-active-tracking-id id)
    (message "emcore: tracking started on #%s" (alist-get 'ticketNo ticket))))

;;;###autoload
(defun emcore-clock-out ()
  "Stop the running time-tracking entry."
  (interactive)
  (let ((id (or emcore-active-tracking-id
                (alist-get 'timeTrackingId (emcore-active-tracking)))))
    (unless id (user-error "emcore: no active time tracking"))
    (emcore-tracking-stop id)
    (setq emcore-active-tracking-id nil)
    (message "emcore: tracking stopped")))

;;;###autoload
(defun emcore-comment ()
  "Set the comment on the running time-tracking entry."
  (interactive)
  (let ((id (or emcore-active-tracking-id
                (alist-get 'timeTrackingId (emcore-active-tracking)))))
    (unless id (user-error "emcore: no active time tracking"))
    (emcore-tracking-set-comment id (read-string "Comment: "))
    (message "emcore: comment set")))

(declare-function org-read-date "org" (&optional with-time to-time from-string prompt
                                                 default-time default-input inactive))

;;;###autoload
(defun emcore-break (start end)
  "Record a break from START to END (prompted as org dates with time)."
  (interactive
   (progn (require 'org)
          (list (org-read-date t t nil "Break start")
                (org-read-date t t nil "Break end"))))
  (emcore-tracking-create "break" start end)
  (message "emcore: break recorded"))

(provide 'emcore)
;;; emcore.el ends here
