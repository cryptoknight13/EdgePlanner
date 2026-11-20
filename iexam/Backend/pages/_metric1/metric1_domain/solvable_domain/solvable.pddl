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
        (has-n1-system-1-dot-1 windows-7-spi-or-windows-server-2008-r2-spi-or-windows-8-or-windows-8-dot-1-or-windows-server-2012-gold-or-windows-server-2012-r2)
        (has-n1-struct-1-dot-1 http-requests)
        (has-n1-function-1-dot-1 http-dot-system)
        (has-n2-system-1-dot-1 windows-xp-64-bit-edition-or-windows-server-2003-or-windows-server-2003-64-bit-edition-or-exchange-server-2003-or-exchange-routing-engine-component)
        (has-n2-driver-1-dot-1 smtp-component)
        (has-n2-driver-1-dot-2 exchange-routing-engine-component)
        (has-n2-cause-1-dot-1 malicious-dns-response-message-with-improper-length-values)
        (has-n3-cause-1-dot-1 improper-request-handling)
        (has-n3-driver-1-dot-1 request-handling)
        (has-n3-system-1-dot-1 windows-dns-server)
        (has-n4-system-1-dot-1 pure-ftpd-1-dot-0-dot-49)
        (has-n4-struct-1-dot-1 utils-dot-c)
        (has-n4-cause-1-dot-1 out-of-bounds-read-in-pure_strcmp)
        (has-n4-function-1-dot-1 pure_strcmp-function)
        (has-n5-system-1-dot-1 postgresql-9-dot-3-through-10)
        (has-n5-driver-1-dot-1 query-behavior-modification)
        (has-n5-cause-1-dot-1 allowed-user-to-modify-query-behavior)
        (has-n6-system-1-dot-1 ganglia-3-dot-1-dot-1)
        (has-n6-driver-1-dot-1 gmetad-slash-server-dot-c)
        (has-n6-struct-1-dot-1 long-pathname-request-to-gmetad-service)
        (has-n6-function-1-dot-1 process_path-function)
    )

    (:goal
    (exploited-n6 admin-server)
)

)