(define (problem netproblem)
    (:domain netdomain)
    (:objects
        web-server - node
        mail-server - node
        dns-server - node
        ftp-server - node
        database-server - node
        admin-server - node
        windows-7-spi-or-windows-server-2008-r2-spi-or-windows-8-or-windows-8-dot-1-or-windows-server-2012-gold-or-windows-server-2012-r2 - system
        http-requests - struct
        http-dot-system - function
        windows-xp-64-bit-edition-or-windows-server-2003-or-windows-server-2003-64-bit-edition-or-exchange-server-2003-or-exchange-routing-engine-component - system
        smtp-component - driver
        exchange-routing-engine-component - driver
        malicious-dns-response-message-with-improper-length-values - cause
        improper-request-handling - cause
        request-handling - driver
        windows-dns-server - system
        pure-ftpd-1-dot-0-dot-49 - system
        utils-dot-c - struct
        out-of-bounds-read-in-pure_strcmp - cause
        pure_strcmp-function - function
        postgresql-9-dot-3-through-10 - system
        query-behavior-modification - driver
        allowed-user-to-modify-query-behavior - cause
        ganglia-3-dot-1-dot-1 - system
        gmetad-slash-server-dot-c - driver
        long-pathname-request-to-gmetad-service - struct
        process_path-function - function
        attacker1 - adversary
    )

    (:init
        (has-service-up-n1 web-server)
        (has-service-up-n2 mail-server)
        (has-service-up-n3 dns-server)
        (has-service-up-n4 ftp-server)
        (has-service-up-n5 database-server)
        (has-service-up-n6 admin-server)
        (has-attacker attacker1)
        (can-ping web-server dns-server)
        (can-ping dns-server database-server)
        (can-ping database-server admin-server)
        (can-ping mail-server ftp-server)
        (can-ping ftp-server admin-server)
    )

    (:goal
    (exploited-n6 admin-server)
)

)