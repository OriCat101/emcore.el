;;; emcore-org.el --- Org integration for emcore  -*- lexical-binding: t; -*-

;; Author: Ori <okayihan@emotions.ch>
;; Package-Requires: ((emacs "28.1"))
;; Keywords: tools, outlines

;;; Commentary:

;; Org-mode integration for emcore.el:
;;
;; - Dynamic blocks (refresh with `org-dblock-update', C-c C-x C-u):
;;
;;     #+BEGIN: emcore-ticket :no 1234
;;     #+END:
;;
;;     #+BEGIN: emcore-analysis :start "2026-09-01" :end "2026-09-30" :days t
;;     #+END:
;;
;;   The ticket block renders the ticket's fields, description and its
;;   comment/change history (`:comments nil' to skip the history, which
;;   costs an extra page scrape).  The analysis block renders the TRS
;;   worked/expected summary; `:start'/`:end' are inclusive local dates
;;   defaulting to the current month so far.
;;
;; - `emcore-org-clock-mode': a global minor mode that mirrors
;;   org-clock to TRS time tracking.  Clocking into a headline with an
;;   EMCORE_TICKET property (inherited; ticket number or ticketId)
;;   creates a running working-time entry linked to that ticket with
;;   the headline as comment; clocking out stops it; cancelling the
;;   clock deletes it.

;;; Code:

(require 'emcore)
(require 'org)
(require 'org-clock)
(require 'org-table)
(require 'shr)
(require 'dom)

;;;; HTML rendering helpers

(defun emcore-org--dom-to-text (dom)
  "Render DOM (from libxml) to plain text via shr."
  (if (null dom) ""
    (with-temp-buffer
      (let ((shr-width 70)
            (shr-use-fonts nil)
            (shr-inhibit-images t)
            (shr-bullet "- "))
        (shr-insert-document dom))
      (string-trim (buffer-substring-no-properties (point-min) (point-max))))))

(defun emcore-org--html-to-text (html)
  (if (or (null html) (string-empty-p html)) ""
    (emcore-org--dom-to-text
     (with-temp-buffer
       (insert html)
       (libxml-parse-html-region (point-min) (point-max))))))

(defun emcore-org--indent (text &optional prefix)
  "Indent every line of TEXT so it cannot break org structure."
  (let ((prefix (or prefix "  ")))
    (mapconcat (lambda (line) (if (string-empty-p line) "" (concat prefix line)))
               (split-string text "\n")
               "\n")))

(defun emcore-org--insert-table (rows)
  "Insert ROWS (lists of strings; the symbol `hline' inserts a rule) and align."
  (let ((start (point)))
    (dolist (row rows)
      (if (eq row 'hline)
          (insert "|-|\n")
        (insert "| " (mapconcat #'identity row " | ") " |\n")))
    (save-excursion
      (goto-char start)
      (org-table-align))))

;;;; Ticket dynamic block

(defun emcore-org--status-label (code)
  (if (or (null code) (string-empty-p code))
      ""
    (capitalize (string-replace "_" " " code))))

(defun emcore-org--field (ticket key)
  (let ((v (emcore-get ticket key)))
    (cond ((null v) nil)
          ((and (stringp v) (string-empty-p v)) nil)
          ((numberp v) (format "%s" v))
          (t v))))

(defun emcore-org--effort-line (ticket)
  (let ((parts nil))
    (pcase-dolist (`(,key . ,label) '((estimatedEffort . "est")
                                      (offeredEffort . "offered")
                                      (billableEffort . "billable")))
      (let ((v (emcore-get ticket key)))
        (when (and v (numberp (string-to-number (format "%s" v)))
                   (> (string-to-number (format "%s" v)) 0))
          (push (format "%s %s" label
                        (emcore-format-minutes (string-to-number (format "%s" v))))
                parts))))
    (and parts (string-join (nreverse parts) " · "))))

(defun emcore-org--insert-history (ticket-no)
  (let ((entries (emcore-ticket-history ticket-no)))
    (if (null entries)
        (insert "No history.\n")
      (dolist (e entries)
        (let ((author (or (alist-get 'author e) "?"))
              (time (or (alist-get 'time e) ""))
              (tracking-p (equal (alist-get 'source e) "timetrackings"))
              (comment (emcore-org--dom-to-text (alist-get 'comment e)))
              (changes (alist-get 'changes e)))
          (insert (format "- %s — %s%s\n" author time
                          (if tracking-p " (time tracking)" "")))
          (unless (string-empty-p comment)
            (insert (emcore-org--indent comment) "\n"))
          (dolist (c changes)
            (insert "  ~ " c "\n")))))))

;;;###autoload
(defun org-dblock-write:emcore-ticket (params)
  "Write the emcore-ticket dynamic block.
PARAMS: `:no' (required, ticket number or ticketId), `:comments'
\(default t, set nil to skip the history scrape)."
  (let* ((no (or (plist-get params :no)
                 (user-error "emcore-ticket block needs :no")))
         (no-str (format "%s" no))
         (ticket-id (if (= (length no-str) 35) no-str (emcore-ticket-id no-str)))
         (ticket (emcore-ticket ticket-id))
         (comments-p (if (plist-member params :comments)
                         (plist-get params :comments)
                       t))
         (ticket-no (or (emcore-org--field ticket 'ticketNo) no-str))
         (field (apply-partially #'emcore-org--field ticket)))
    (insert (format "*[#%s] %s*\n" ticket-no (or (funcall field 'title) "")))
    (emcore-org--insert-table
     (delq nil
           (list
            (list "Status" (emcore-org--status-label (funcall field 'ticketStatusCode)))
            (list "Priority" (or (funcall field 'priority) ""))
            (when (funcall field 'assignedToName)
              (list "Assigned" (funcall field 'assignedToName)))
            (when (or (funcall field 'firmName) (funcall field 'projectTitle))
              (list "Firm" (string-join
                            (delq nil (list (funcall field 'firmName)
                                            (funcall field 'projectTitle)))
                            " — ")))
            (when (or (funcall field 'startDate) (funcall field 'endDate))
              (list "Dates" (format "%s → %s"
                                    (or (funcall field 'startDate) "…")
                                    (or (funcall field 'endDate) "…"))))
            (when (funcall field 'percentageComplete)
              (list "Progress" (concat (funcall field 'percentageComplete) "%")))
            (when (emcore-org--effort-line ticket)
              (list "Effort" (emcore-org--effort-line ticket)))
            (when (funcall field 'parentTicketNo)
              (list "Parent" (format "#%s %s"
                                     (funcall field 'parentTicketNo)
                                     (or (funcall field 'parentTitle) "")))))))
    (let ((desc (emcore-org--html-to-text (funcall field 'description))))
      (unless (string-empty-p desc)
        (insert "\nDescription:\n" (emcore-org--indent desc) "\n")))
    (when comments-p
      (insert "\nHistory:\n")
      (emcore-org--insert-history ticket-no))))

;;;; Analysis dynamic block

(defun emcore-org--day-worked (day)
  (apply #'+ (mapcar (lambda (e)
                       (let ((m (alist-get 'minutes e)))
                         (if (and (equal (alist-get 'source e) "timeTracking")
                                  (numberp m))
                             m
                           0)))
                     (alist-get 'entries day))))

(defun emcore-org--day-absence (day)
  (apply #'+ (mapcar (lambda (e)
                       (let ((m (alist-get 'minutes e)))
                         (if (and (member (alist-get 'source e) '("leave" "holiday"))
                                  (numberp m))
                             m
                           0)))
                     (alist-get 'entries day))))

(defun emcore-org--signed-minutes (minutes)
  (concat (if (>= minutes 0) "+" "") (emcore-format-minutes minutes)))

;;;###autoload
(defun org-dblock-write:emcore-analysis (params)
  "Write the emcore-analysis dynamic block.
PARAMS: `:start' and `:end' (inclusive \"YYYY-MM-DD\" local dates,
default: first of the current month to today), `:days' (non-nil adds a
per-day table), `:user' (userId, needs the trs-report permission)."
  (let* ((start-str (or (plist-get params :start) (format-time-string "%Y-%m-01")))
         (end-str (or (plist-get params :end) (format-time-string "%Y-%m-%d")))
         (start (emcore--date-to-time start-str))
         (end (emcore--date-to-time end-str 1))
         (user (plist-get params :user))
         (summary (alist-get 'summary (emcore-analysis start end user)))
         (expected (or (alist-get 'expectedMinutes summary) 0))
         (worked (or (alist-get 'workedMinutes summary) 0))
         (holiday (or (alist-get 'holidayMinutes summary) 0))
         (leave (or (alist-get 'leaveMinutes summary) 0))
         (balance (- (+ worked holiday leave) expected)))
    (insert (format "Time %s – %s" start-str end-str)
            (if user (format " (user %s)" user) "")
            "\n")
    (emcore-org--insert-table
     (list (list "Expected" (emcore-format-minutes expected))
           (list "Worked" (emcore-format-minutes worked))
           (list "Holidays" (emcore-format-minutes holiday))
           (list "Leaves" (emcore-format-minutes leave))
           'hline
           (list "Balance" (emcore-org--signed-minutes balance))))
    (when (plist-get params :days)
      (let ((days (alist-get 'days (emcore-analysis-days start end user))))
        (insert "\n")
        (emcore-org--insert-table
         (append
          (list (list "Date" "Day" "Expected" "Worked" "Absence" "±") 'hline)
          (mapcar
           (lambda (day)
             (let* ((date (alist-get 'date day))
                    (exp (or (alist-get 'expectedMinutes day) 0))
                    (wrk (emcore-org--day-worked day))
                    (abs (emcore-org--day-absence day)))
               (list date
                     (format-time-string "%a" (emcore--date-to-time date))
                     (emcore-format-minutes exp)
                     (emcore-format-minutes wrk)
                     (emcore-format-minutes abs)
                     (emcore-org--signed-minutes (- (+ wrk abs) exp)))))
           days)))))))

;;;; Block insertion commands

;;;###autoload
(defun emcore-insert-ticket-block ()
  "Insert an emcore-ticket dynamic block, prompting for the ticket."
  (interactive)
  (let ((no (alist-get 'ticketNo (emcore-read-ticket))))
    (org-create-dblock (list :name "emcore-ticket"
                             :no (if (stringp no) (string-to-number no) no)))
    (org-update-dblock)))

;;;###autoload
(defun emcore-insert-analysis-block ()
  "Insert an emcore-analysis dynamic block for the current month."
  (interactive)
  (org-create-dblock (list :name "emcore-analysis" :days t))
  (org-update-dblock))

;;;; org-clock integration

(defvar emcore-org--hd-marker nil
  "Marker to the headline whose clock is mirrored to emcore.")

(defun emcore-org--marker-tracking-id ()
  (or (and (markerp emcore-org--hd-marker)
           (marker-buffer emcore-org--hd-marker)
           (org-entry-get emcore-org--hd-marker "EMCORE_TRACKING_ID"))
      (ignore-errors (org-entry-get nil "EMCORE_TRACKING_ID"))))

(defun emcore-org--clear ()
  (when (and (markerp emcore-org--hd-marker)
             (marker-buffer emcore-org--hd-marker))
    (ignore-errors
      (org-entry-delete emcore-org--hd-marker "EMCORE_TRACKING_ID"))
    (set-marker emcore-org--hd-marker nil))
  (setq emcore-org--hd-marker nil
        emcore-active-tracking-id nil))

(defun emcore-org--clock-in ()
  (when-let* ((ticket (org-entry-get org-clock-marker "EMCORE_TICKET" t)))
    (condition-case err
        (let* ((ticket-id (if (= (length ticket) 35)
                              ticket
                            (emcore-ticket-id ticket)))
               (heading (org-with-point-at org-clock-hd-marker
                          (org-get-heading t t t t)))
               (id (emcore-start-tracking (or org-clock-start-time (current-time))
                                          heading ticket-id)))
          (setq emcore-active-tracking-id id
                emcore-org--hd-marker (copy-marker org-clock-hd-marker))
          (org-entry-put org-clock-hd-marker "EMCORE_TRACKING_ID" id)
          (message "emcore: tracking ticket %s" ticket))
      (error (message "emcore: clock-in sync failed: %s"
                      (error-message-string err))))))

(defun emcore-org--clock-out ()
  (when-let* ((id (or emcore-active-tracking-id
                      (emcore-org--marker-tracking-id))))
    (condition-case err
        (progn
          (emcore-tracking-stop id)
          (emcore-org--clear)
          (message "emcore: tracking stopped"))
      (error (message "emcore: clock-out sync failed: %s"
                      (error-message-string err))))))

(defun emcore-org--clock-cancel ()
  (when-let* ((id (or emcore-active-tracking-id
                      (emcore-org--marker-tracking-id))))
    (condition-case err
        (progn
          (emcore-tracking-delete id)
          (emcore-org--clear)
          (message "emcore: tracking discarded"))
      (error (message "emcore: cancel sync failed: %s"
                      (error-message-string err))))))

;;;###autoload
(define-minor-mode emcore-org-clock-mode
  "Mirror org-clock to emcore TRS time tracking.
Clocking into a headline with an EMCORE_TICKET property (inherited;
ticket number or ticketId) creates a running working-time entry linked
to that ticket, with the headline as comment.  Clocking out stops the
entry, cancelling the clock deletes it."
  :global t
  :group 'emcore
  (if emcore-org-clock-mode
      (progn
        (add-hook 'org-clock-in-hook #'emcore-org--clock-in)
        (add-hook 'org-clock-out-hook #'emcore-org--clock-out)
        (add-hook 'org-clock-cancel-hook #'emcore-org--clock-cancel))
    (remove-hook 'org-clock-in-hook #'emcore-org--clock-in)
    (remove-hook 'org-clock-out-hook #'emcore-org--clock-out)
    (remove-hook 'org-clock-cancel-hook #'emcore-org--clock-cancel)))

(provide 'emcore-org)
;;; emcore-org.el ends here
