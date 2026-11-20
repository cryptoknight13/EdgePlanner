(define (domain netdomain)
    (:requirements :strips :typing)
    (:types node function struct driver system cause adversary)

    (:predicates
      (has-service-up-n0 ?Node - node)
      (has-service-up-n1 ?Node - node)
      (has-service-up-n2 ?Node - node)
      (has-service-up-n3 ?Node - node)
      (has-service-up-n4 ?Node - node)
      (has-service-up-n5 ?Node - node)
      (has-service-up-n6 ?Node - node)
      (has-attacker ?atk - adversary)
      (can-ping ?Node1 - node ?Node2 - node)
      (has-connection-to ?Node - node)
      (has-access-to-mail-server-node ?node - node ?atk - adversary)
      (has-access-to-web-server-node ?node - node ?atk - adversary)
        (exploited-n1 ?Node - node)
        (has-n1-system-1-dot-1 ?system1 - system)
        (has-n1-struct-1-dot-1 ?struct1 - struct)
        (has-n1-function-1-dot-1 ?function1 - function)
        (exploited-n2 ?Node - node)
        (has-n2-system-1-dot-1 ?system1 - system)
        (has-n2-driver-1-dot-1 ?driver1 - driver)
        (has-n2-driver-1-dot-2 ?driver2 - driver)
        (has-n2-cause-1-dot-1 ?cause1 - cause)
        (exploited-n3 ?Node - node)
        (has-n3-cause-1-dot-1 ?cause1 - cause)
        (has-n3-driver-1-dot-1 ?driver1 - driver)
        (has-n3-system-1-dot-1 ?system1 - system)
        (exploited-n4 ?Node - node)
        (has-n4-system-1-dot-1 ?system1 - system)
        (has-n4-struct-1-dot-1 ?struct1 - struct)
        (has-n4-cause-1-dot-1 ?cause1 - cause)
        (has-n4-function-1-dot-1 ?function1 - function)
        (exploited-n5 ?Node - node)
        (has-n5-system-1-dot-1 ?system1 - system)
        (has-n5-driver-1-dot-1 ?driver1 - driver)
        (has-n5-cause-1-dot-1 ?cause1 - cause)
        (exploited-n6 ?Node - node)
        (has-n6-system-1-dot-1 ?system1 - system)
        (has-n6-driver-1-dot-1 ?driver1 - driver)
        (has-n6-struct-1-dot-1 ?struct1 - struct)
        (has-n6-function-1-dot-1 ?function1 - function)
    )

(:action connectivity-edge-between-web-server-and-dns-server
:parameters (?node1 - node ?node2 - node)
:precondition
(and
( has-service-up-n1 ?node1 )
( has-service-up-n3 ?node2 )
( can-ping ?node1 ?node2 )

)
:effect
(and
( has-connection-to ?node2 )

)
)

(:action attacker-exploit-cve-2015-1635-to-compromise-web-server
:parameters (?node - node ?atk - adversary ?system1 - system ?struct1 - struct ?function1 - function)
:precondition
(and
( has-service-up-n1 ?node )
( has-n1-struct-1-dot-1 ?struct1 )
( has-n1-function-1-dot-1 ?function1 )
( has-n1-system-1-dot-1 ?system1 )
( has-access-to-web-server-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2020-9365-to-compromise-ftp-server-via-mail-server
:parameters (?node2 - node ?node1 - node ?system1 - system ?struct1 - struct ?cause1 - cause ?function1 - function)
:precondition
(and
( has-service-up-n4 ?node2 )
( has-n4-function-1-dot-1 ?function1 )
( has-n4-cause-1-dot-1 ?cause1 )
( has-n4-struct-1-dot-1 ?struct1 )
( has-n4-system-1-dot-1 ?system1 )
( exploited-n2 ?node1 )
( can-ping ?node1 ?node2 )
( has-service-up-n2 ?node1 )

)
:effect
(and
( exploited-n4 ?node2 )

)
)

(:action attacker-exploit-cve-2009-0241-to-compromise-admin-server-via-database-server
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver ?struct1 - struct ?function1 - function)
:precondition
(and
( has-n6-struct-1-dot-1 ?struct1 )
( has-n6-driver-1-dot-1 ?driver1 )
( exploited-n5 ?node1 )
( has-service-up-n6 ?node2 )
( has-service-up-n5 ?node1 )
( has-n6-system-1-dot-1 ?system1 )
( has-n6-function-1-dot-1 ?function1 )
( can-ping ?node1 ?node2 )

)
:effect
(and
( exploited-n6 ?node2 )

)
)

(:action attacker-exploit-cve-2018-1058-to-compromise-database-server-via-dns-server
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver ?cause1 - cause)
:precondition
(and
( has-n5-driver-1-dot-1 ?driver1 )
( can-ping ?node1 ?node2 )
( has-service-up-n3 ?node1 )
( has-n5-cause-1-dot-1 ?cause1 )
( has-service-up-n5 ?node2 )
( exploited-n3 ?node1 )
( has-n5-system-1-dot-1 ?system1 )

)
:effect
(and
( exploited-n5 ?node2 )

)
)

(:action attacker-exploit-cve-2009-0241-to-compromise-admin-server-via-ftp-server
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver ?struct1 - struct ?function1 - function)
:precondition
(and
( has-n6-struct-1-dot-1 ?struct1 )
( exploited-n4 ?node1 )
( has-n6-function-1-dot-1 ?function1 )
( has-n6-system-1-dot-1 ?system1 )
( has-n6-driver-1-dot-1 ?driver1 )
( can-ping ?node1 ?node2 )
( has-service-up-n6 ?node2 )
( has-service-up-n4 ?node1 )

)
:effect
(and
( exploited-n6 ?node2 )

)
)

(:action connectivity-edge-between-ftp-server-and-admin-server
:parameters (?node1 - node ?node2 - node)
:precondition
(and
( has-connection-to ?node1 )
( has-service-up-n6 ?node2 )
( can-ping ?node1 ?node2 )
( has-service-up-n4 ?node1 )

)
:effect
(and
( has-connection-to ?node2 )

)
)

(:action connectivity-edge-between-dns-server-and-database-server
:parameters (?node1 - node ?node2 - node)
:precondition
(and
( can-ping ?node1 ?node2 )
( has-connection-to ?node1 )
( has-service-up-n3 ?node1 )
( has-service-up-n5 ?node2 )

)
:effect
(and
( has-connection-to ?node2 )

)
)

(:action attacker-has-access-to-mail-server
:parameters (?node - node ?atk - adversary)
:precondition
(and
( has-attacker ?atk )
( has-service-up-n2 ?node )

)
:effect
(and
( has-access-to-mail-server-node ?node ?atk )

)
)

(:action connectivity-edge-between-database-server-and-admin-server
:parameters (?node1 - node ?node2 - node)
:precondition
(and
( has-connection-to ?node1 )
( has-service-up-n6 ?node2 )
( has-service-up-n5 ?node1 )
( can-ping ?node1 ?node2 )

)
:effect
(and
( has-connection-to ?node2 )

)
)

(:action attacker-exploit-cve-2004-0840-to-compromise-mail-server
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver ?driver2 - driver ?cause1 - cause)
:precondition
(and
( has-n2-system-1-dot-1 ?system1 )
( has-n2-cause-1-dot-1 ?cause1 )
( has-n2-driver-1-dot-1 ?driver1 )
( has-access-to-mail-server-node ?node ?atk )
( has-n2-driver-1-dot-2 ?driver2 )
( has-service-up-n2 ?node )

)
:effect
(and
( exploited-n2 ?node )

)
)

(:action connectivity-edge-between-mail-server-and-ftp-server
:parameters (?node1 - node ?node2 - node)
:precondition
(and
( has-service-up-n2 ?node1 )
( has-service-up-n4 ?node2 )
( can-ping ?node1 ?node2 )

)
:effect
(and
( has-connection-to ?node2 )

)
)

(:action attacker-has-access-to-web-server
:parameters (?node - node ?atk - adversary)
:precondition
(and
( has-attacker ?atk )
( has-service-up-n1 ?node )

)
:effect
(and
( has-access-to-web-server-node ?node ?atk )

)
)

(:action attacker-exploit-cve-2020-1350-to-compromise-dns-server-via-web-server
:parameters (?node2 - node ?node1 - node ?cause1 - cause ?driver1 - driver ?system1 - system)
:precondition
(and
( has-n3-driver-1-dot-1 ?driver1 )
( can-ping ?node1 ?node2 )
( has-n3-cause-1-dot-1 ?cause1 )
( exploited-n1 ?node1 )
( has-service-up-n3 ?node2 )
( has-n3-system-1-dot-1 ?system1 )
( has-service-up-n1 ?node1 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)


 )