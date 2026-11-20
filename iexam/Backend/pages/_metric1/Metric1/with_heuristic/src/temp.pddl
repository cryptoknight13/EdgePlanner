(define (domain netdomain)
    (:requirements :strips :typing)
    (:types node function struct driver system cause adversary)

    (:predicates
      (has-service-up-n0 ?Node - node)
      (has-service-up-n1 ?Node - node)
      (has-service-up-n2 ?Node - node)
      (has-service-up-n3 ?Node - node)
      (has-attacker ?atk - adversary)
      (can-ping ?Node1 - node ?Node2 - node)
      (has-connection-to ?Node - node)
      (has-access-to-linksys-wrt3200acm-node ?node - node ?atk - adversary)
        (exploited-n1 ?Node - node)
        (has-n1-system-1-dot-1 ?system1 - system)
        (has-n1-driver-1-dot-1 ?driver1 - driver)
        (has-n1-system-2-dot-1 ?system1 - system)
        (has-n1-driver-2-dot-1 ?driver1 - driver)
        (has-n1-system-3-dot-1 ?system1 - system)
        (has-n1-driver-3-dot-1 ?driver1 - driver)
        (has-n1-system-4-dot-1 ?system1 - system)
        (has-n1-driver-4-dot-1 ?driver1 - driver)
        (has-n1-system-5-dot-1 ?system1 - system)
        (has-n1-driver-5-dot-1 ?driver1 - driver)
        (has-n1-system-6-dot-1 ?system1 - system)
        (has-n1-driver-6-dot-1 ?driver1 - driver)
        (has-n1-system-7-dot-1 ?system1 - system)
        (has-n1-driver-7-dot-1 ?driver1 - driver)
        (has-n1-system-8-dot-1 ?system1 - system)
        (has-n1-driver-8-dot-1 ?driver1 - driver)
        (has-n1-system-9-dot-1 ?system1 - system)
        (has-n1-driver-9-dot-1 ?driver1 - driver)
        (has-n1-system-10-dot-1 ?system1 - system)
        (has-n1-driver-10-dot-1 ?driver1 - driver)
        (has-n1-system-11-dot-1 ?system1 - system)
        (has-n1-driver-11-dot-1 ?driver1 - driver)
        (has-n1-system-12-dot-1 ?system1 - system)
        (has-n1-driver-12-dot-1 ?driver1 - driver)
        (has-n1-system-13-dot-1 ?system1 - system)
        (has-n1-driver-13-dot-1 ?driver1 - driver)
        (has-n1-system-14-dot-1 ?system1 - system)
        (has-n1-driver-14-dot-1 ?driver1 - driver)
        (has-n1-system-15-dot-1 ?system1 - system)
        (has-n1-driver-15-dot-1 ?driver1 - driver)
        (has-n1-system-16-dot-1 ?system1 - system)
        (has-n1-driver-16-dot-1 ?driver1 - driver)
        (has-n1-system-17-dot-1 ?system1 - system)
        (has-n1-driver-17-dot-1 ?driver1 - driver)
        (has-n1-system-18-dot-1 ?system1 - system)
        (has-n1-driver-18-dot-1 ?driver1 - driver)
        (has-n1-system-19-dot-1 ?system1 - system)
        (has-n1-driver-19-dot-1 ?driver1 - driver)
        (has-n1-system-20-dot-1 ?system1 - system)
        (has-n1-driver-20-dot-1 ?driver1 - driver)
        (has-n1-system-21-dot-1 ?system1 - system)
        (has-n1-driver-21-dot-1 ?driver1 - driver)
        (has-n1-system-22-dot-1 ?system1 - system)
        (has-n1-driver-22-dot-1 ?driver1 - driver)
        (has-n1-system-23-dot-1 ?system1 - system)
        (has-n1-driver-23-dot-1 ?driver1 - driver)
        (has-n1-system-24-dot-1 ?system1 - system)
        (has-n1-driver-24-dot-1 ?driver1 - driver)
        (has-n1-system-25-dot-1 ?system1 - system)
        (has-n1-driver-25-dot-1 ?driver1 - driver)
        (has-n1-system-26-dot-1 ?system1 - system)
        (has-n1-driver-26-dot-1 ?driver1 - driver)
        (has-n1-system-27-dot-1 ?system1 - system)
        (has-n1-driver-27-dot-1 ?driver1 - driver)
        (has-n1-system-28-dot-1 ?system1 - system)
        (has-n1-driver-28-dot-1 ?driver1 - driver)
        (has-n1-system-29-dot-1 ?system1 - system)
        (has-n1-driver-29-dot-1 ?driver1 - driver)
        (has-n1-system-30-dot-1 ?system1 - system)
        (has-n1-driver-30-dot-1 ?driver1 - driver)
        (has-n1-system-31-dot-1 ?system1 - system)
        (has-n1-driver-31-dot-1 ?driver1 - driver)
        (has-n1-system-32-dot-1 ?system1 - system)
        (has-n1-driver-32-dot-1 ?driver1 - driver)
        (has-n1-system-33-dot-1 ?system1 - system)
        (has-n1-driver-33-dot-1 ?driver1 - driver)
        (has-n1-system-34-dot-1 ?system1 - system)
        (has-n1-driver-34-dot-1 ?driver1 - driver)
        (has-n1-system-35-dot-1 ?system1 - system)
        (has-n1-driver-35-dot-1 ?driver1 - driver)
        (has-n1-system-36-dot-1 ?system1 - system)
        (has-n1-driver-36-dot-1 ?driver1 - driver)
        (has-n1-system-37-dot-1 ?system1 - system)
        (has-n1-driver-37-dot-1 ?driver1 - driver)
        (has-n1-system-38-dot-1 ?system1 - system)
        (has-n1-driver-38-dot-1 ?driver1 - driver)
        (has-n1-system-39-dot-1 ?system1 - system)
        (has-n1-driver-39-dot-1 ?driver1 - driver)
        (has-n1-system-40-dot-1 ?system1 - system)
        (has-n1-driver-40-dot-1 ?driver1 - driver)
        (has-n1-system-41-dot-1 ?system1 - system)
        (has-n1-driver-41-dot-1 ?driver1 - driver)
        (has-n1-system-42-dot-1 ?system1 - system)
        (has-n1-driver-42-dot-1 ?driver1 - driver)
        (has-n1-system-43-dot-1 ?system1 - system)
        (has-n1-driver-43-dot-1 ?driver1 - driver)
        (has-n1-system-44-dot-1 ?system1 - system)
        (has-n1-driver-44-dot-1 ?driver1 - driver)
        (has-n1-system-45-dot-1 ?system1 - system)
        (has-n1-driver-45-dot-1 ?driver1 - driver)
        (has-n1-system-46-dot-1 ?system1 - system)
        (has-n1-driver-46-dot-1 ?driver1 - driver)
        (has-n1-system-47-dot-1 ?system1 - system)
        (has-n1-driver-47-dot-1 ?driver1 - driver)
        (has-n1-system-48-dot-1 ?system1 - system)
        (has-n1-driver-48-dot-1 ?driver1 - driver)
        (has-n1-system-49-dot-1 ?system1 - system)
        (has-n1-driver-49-dot-1 ?driver1 - driver)
        (has-n1-system-50-dot-1 ?system1 - system)
        (has-n1-driver-50-dot-1 ?driver1 - driver)
        (has-n1-system-51-dot-1 ?system1 - system)
        (has-n1-driver-51-dot-1 ?driver1 - driver)
        (has-n1-system-52-dot-1 ?system1 - system)
        (has-n1-driver-52-dot-1 ?driver1 - driver)
        (has-n1-system-53-dot-1 ?system1 - system)
        (has-n1-driver-53-dot-1 ?driver1 - driver)
        (has-n1-system-54-dot-1 ?system1 - system)
        (has-n1-driver-54-dot-1 ?driver1 - driver)
        (has-n1-system-55-dot-1 ?system1 - system)
        (has-n1-driver-55-dot-1 ?driver1 - driver)
        (has-n1-system-56-dot-1 ?system1 - system)
        (has-n1-driver-56-dot-1 ?driver1 - driver)
        (has-n1-system-57-dot-1 ?system1 - system)
        (has-n1-driver-57-dot-1 ?driver1 - driver)
        (has-n1-system-58-dot-1 ?system1 - system)
        (has-n1-driver-58-dot-1 ?driver1 - driver)
        (has-n1-system-59-dot-1 ?system1 - system)
        (has-n1-driver-59-dot-1 ?driver1 - driver)
        (has-n1-system-60-dot-1 ?system1 - system)
        (has-n1-driver-60-dot-1 ?driver1 - driver)
        (has-n1-system-61-dot-1 ?system1 - system)
        (has-n1-driver-61-dot-1 ?driver1 - driver)
        (has-n1-system-62-dot-1 ?system1 - system)
        (has-n1-driver-62-dot-1 ?driver1 - driver)
        (has-n1-system-63-dot-1 ?system1 - system)
        (has-n1-driver-63-dot-1 ?driver1 - driver)
        (has-n1-system-64-dot-1 ?system1 - system)
        (has-n1-driver-64-dot-1 ?driver1 - driver)
        (has-n1-system-65-dot-1 ?system1 - system)
        (has-n1-driver-65-dot-1 ?driver1 - driver)
        (has-n1-system-66-dot-1 ?system1 - system)
        (has-n1-driver-66-dot-1 ?driver1 - driver)
        (has-n1-system-67-dot-1 ?system1 - system)
        (has-n1-driver-67-dot-1 ?driver1 - driver)
        (has-n1-system-68-dot-1 ?system1 - system)
        (has-n1-driver-68-dot-1 ?driver1 - driver)
        (has-n1-system-69-dot-1 ?system1 - system)
        (has-n1-driver-69-dot-1 ?driver1 - driver)
        (exploited-n2 ?Node - node)
        (has-n2-system-1-dot-1 ?system1 - system)
        (has-n2-driver-1-dot-1 ?driver1 - driver)
        (has-n2-system-2-dot-1 ?system1 - system)
        (has-n2-driver-2-dot-1 ?driver1 - driver)
        (has-n2-system-3-dot-1 ?system1 - system)
        (has-n2-driver-3-dot-1 ?driver1 - driver)
        (has-n2-system-4-dot-1 ?system1 - system)
        (has-n2-driver-4-dot-1 ?driver1 - driver)
        (has-n2-system-5-dot-1 ?system1 - system)
        (has-n2-driver-5-dot-1 ?driver1 - driver)
        (has-n2-system-6-dot-1 ?system1 - system)
        (has-n2-driver-6-dot-1 ?driver1 - driver)
        (has-n2-system-7-dot-1 ?system1 - system)
        (has-n2-driver-7-dot-1 ?driver1 - driver)
        (has-n2-system-8-dot-1 ?system1 - system)
        (has-n2-driver-8-dot-1 ?driver1 - driver)
        (has-n2-system-9-dot-1 ?system1 - system)
        (has-n2-driver-9-dot-1 ?driver1 - driver)
        (has-n2-system-10-dot-1 ?system1 - system)
        (has-n2-driver-10-dot-1 ?driver1 - driver)
        (has-n2-system-11-dot-1 ?system1 - system)
        (has-n2-driver-11-dot-1 ?driver1 - driver)
        (has-n2-system-12-dot-1 ?system1 - system)
        (has-n2-driver-12-dot-1 ?driver1 - driver)
        (has-n2-system-13-dot-1 ?system1 - system)
        (has-n2-driver-13-dot-1 ?driver1 - driver)
        (has-n2-system-14-dot-1 ?system1 - system)
        (has-n2-driver-14-dot-1 ?driver1 - driver)
        (has-n2-system-15-dot-1 ?system1 - system)
        (has-n2-driver-15-dot-1 ?driver1 - driver)
        (has-n2-system-16-dot-1 ?system1 - system)
        (has-n2-driver-16-dot-1 ?driver1 - driver)
        (has-n2-system-17-dot-1 ?system1 - system)
        (has-n2-driver-17-dot-1 ?driver1 - driver)
        (has-n2-system-18-dot-1 ?system1 - system)
        (has-n2-driver-18-dot-1 ?driver1 - driver)
        (has-n2-system-19-dot-1 ?system1 - system)
        (has-n2-driver-19-dot-1 ?driver1 - driver)
        (has-n2-system-20-dot-1 ?system1 - system)
        (has-n2-driver-20-dot-1 ?driver1 - driver)
        (exploited-n3 ?Node - node)
        (has-n3-system-1-dot-1 ?system1 - system)
        (has-n3-driver-1-dot-1 ?driver1 - driver)
        (has-n3-system-2-dot-1 ?system1 - system)
        (has-n3-driver-2-dot-1 ?driver1 - driver)
        (has-n3-system-3-dot-1 ?system1 - system)
        (has-n3-driver-3-dot-1 ?driver1 - driver)
        (has-n3-system-4-dot-1 ?system1 - system)
        (has-n3-system-5-dot-1 ?system1 - system)
        (has-n3-system-6-dot-1 ?system1 - system)
        (has-n3-system-7-dot-1 ?system1 - system)
        (has-n3-system-8-dot-1 ?system1 - system)
        (has-n3-system-9-dot-1 ?system1 - system)
        (has-n3-system-10-dot-1 ?system1 - system)
        (has-n3-system-11-dot-1 ?system1 - system)
        (has-n3-driver-11-dot-1 ?driver1 - driver)
    )

(:action attacker-exploit-cve-2016-2112-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-17-dot-1 ?system1 )
( has-n1-driver-17-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-60001-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n2-system-17-dot-1 ?system1 )
( exploited-n1 ?node1 )
( has-n2-driver-17-dot-1 ?driver1 )
( can-ping ?node1 ?node2 )
( has-service-up-n2 ?node2 )
( has-service-up-n1 ?node1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2020-25681-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-36-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-system-36-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2022-0934-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-49-dot-1 ?driver1 )
( has-n1-system-49-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2016-2110-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-16-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-16-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2017-12151-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-24-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-24-dot-1 ?system1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2021-20316-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-44-dot-1 ?system1 )
( has-n1-driver-44-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-59997-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n2 ?node2 )
( can-ping ?node1 ?node2 )
( has-service-up-n1 ?node1 )
( has-n2-driver-13-dot-1 ?driver1 )
( has-n2-system-13-dot-1 ?system1 )
( exploited-n1 ?node1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2026-60000-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( exploited-n1 ?node1 )
( has-service-up-n1 ?node1 )
( has-n2-system-16-dot-1 ?system1 )
( has-service-up-n2 ?node2 )
( can-ping ?node1 ?node2 )
( has-n2-driver-16-dot-1 ?driver1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2018-10659-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system)
:precondition
(and
( can-ping ?node1 ?node2 )
( exploited-n1 ?node1 )
( has-service-up-n3 ?node2 )
( has-service-up-n1 ?node1 )
( has-n3-system-5-dot-1 ?system1 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2012-1182-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-8-dot-1 ?driver1 )
( has-n1-system-8-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2016-2124-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-19-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-19-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2020-25685-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-n1-driver-40-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-40-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2015-5252-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-14-dot-1 ?driver1 )
( has-n1-system-14-dot-1 ?system1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2011-0719-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-5-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-5-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2021-3448-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-45-dot-1 ?driver1 )
( has-n1-system-45-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2022-2031-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-50-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-50-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-35414-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( exploited-n1 ?node1 )
( has-service-up-n2 ?node2 )
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )
( has-n2-driver-10-dot-1 ?driver1 )
( has-n2-system-10-dot-1 ?system1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2020-25682-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-37-dot-1 ?driver1 )
( has-n1-system-37-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2020-25684-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-39-dot-1 ?system1 )
( has-n1-driver-39-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2022-38023-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-n1-system-54-dot-1 ?system1 )
( has-n1-driver-54-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-35385-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n2-driver-7-dot-1 ?driver1 )
( can-ping ?node1 ?node2 )
( has-service-up-n1 ?node1 )
( has-n2-system-7-dot-1 ?system1 )
( exploited-n1 ?node1 )
( has-service-up-n2 ?node2 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2023-34968-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-60-dot-1 ?system1 )
( has-n1-driver-60-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2012-5958-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( can-ping ?node1 ?node2 )
( has-n3-driver-1-dot-1 ?driver1 )
( has-service-up-n1 ?node1 )
( has-n3-system-1-dot-1 ?system1 )
( exploited-n1 ?node1 )
( has-service-up-n3 ?node2 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2019-14834-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-33-dot-1 ?driver1 )
( has-n1-system-33-dot-1 ?system1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-106585-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n2-driver-5-dot-1 ?driver1 )
( has-service-up-n2 ?node2 )
( exploited-n1 ?node1 )
( has-n2-system-5-dot-1 ?system1 )
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2023-34967-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-59-dot-1 ?system1 )
( has-n1-driver-59-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-4480-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-68-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-68-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-58224-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-system-69-dot-1 ?system1 )
( has-n1-driver-69-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2010-1635-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-1-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-1-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-106553-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( can-ping ?node1 ?node2 )
( has-n2-driver-2-dot-1 ?driver1 )
( has-service-up-n2 ?node2 )
( exploited-n1 ?node1 )
( has-service-up-n1 ?node1 )
( has-n2-system-2-dot-1 ?system1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2018-10658-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system)
:precondition
(and
( has-service-up-n1 ?node1 )
( has-n3-system-4-dot-1 ?system1 )
( exploited-n1 ?node1 )
( has-service-up-n3 ?node2 )
( can-ping ?node1 ?node2 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2016-2115-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-n1-driver-18-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-18-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2016-8863-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-22-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-22-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2021-3671-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-46-dot-1 ?system1 )
( has-n1-driver-46-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2016-8863-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )
( has-n3-driver-3-dot-1 ?driver1 )
( exploited-n1 ?node1 )
( has-service-up-n3 ?node2 )
( has-n3-system-3-dot-1 ?system1 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2010-1642-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-2-dot-1 ?driver1 )
( has-n1-system-2-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2017-2619-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-27-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-27-dot-1 ?driver1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2022-45141-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-56-dot-1 ?driver1 )
( has-n1-system-56-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2020-25686-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-41-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-41-dot-1 ?driver1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2023-50387-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-64-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-64-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2010-3069-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-n1-system-4-dot-1 ?system1 )
( has-n1-driver-4-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2010-2063-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-n1-system-3-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-3-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-35386-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( can-ping ?node1 ?node2 )
( has-service-up-n1 ?node1 )
( has-n2-driver-8-dot-1 ?driver1 )
( exploited-n1 ?node1 )
( has-n2-system-8-dot-1 ?system1 )
( has-service-up-n2 ?node2 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2020-25683-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-38-dot-1 ?driver1 )
( has-n1-system-38-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-60002-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( can-ping ?node1 ?node2 )
( exploited-n1 ?node1 )
( has-service-up-n1 ?node1 )
( has-n2-system-18-dot-1 ?system1 )
( has-service-up-n2 ?node2 )
( has-n2-driver-18-dot-1 ?driver1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2022-37967-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-53-dot-1 ?driver1 )
( has-n1-system-53-dot-1 ?system1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-73281-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n2 ?node2 )
( exploited-n1 ?node1 )
( has-n2-system-19-dot-1 ?system1 )
( can-ping ?node1 ?node2 )
( has-n2-driver-19-dot-1 ?driver1 )
( has-service-up-n1 ?node1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2026-73282-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n2-system-20-dot-1 ?system1 )
( has-n2-driver-20-dot-1 ?driver1 )
( has-service-up-n1 ?node1 )
( exploited-n1 ?node1 )
( has-service-up-n2 ?node2 )
( can-ping ?node1 ?node2 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2020-13848-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )
( exploited-n1 ?node1 )
( has-n3-driver-11-dot-1 ?driver1 )
( has-service-up-n3 ?node2 )
( has-n3-system-11-dot-1 ?system1 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2023-28450-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-57-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-57-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2022-42898-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-55-dot-1 ?driver1 )
( has-n1-system-55-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2020-25687-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-42-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-42-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-106552-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( can-ping ?node1 ?node2 )
( has-n2-system-1-dot-1 ?system1 )
( has-n2-driver-1-dot-1 ?driver1 )
( exploited-n1 ?node1 )
( has-service-up-n2 ?node2 )
( has-service-up-n1 ?node1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2026-59996-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n2 ?node2 )
( has-service-up-n1 ?node1 )
( has-n2-system-12-dot-1 ?system1 )
( exploited-n1 ?node1 )
( can-ping ?node1 ?node2 )
( has-n2-driver-12-dot-1 ?driver1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2018-10664-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system)
:precondition
(and
( has-service-up-n1 ?node1 )
( has-n3-system-10-dot-1 ?system1 )
( can-ping ?node1 ?node2 )
( has-service-up-n3 ?node2 )
( exploited-n1 ?node1 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2017-9461-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-28-dot-1 ?driver1 )
( has-n1-system-28-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2018-10663-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system)
:precondition
(and
( exploited-n1 ?node1 )
( has-service-up-n1 ?node1 )
( has-n3-system-9-dot-1 ?system1 )
( can-ping ?node1 ?node2 )
( has-service-up-n3 ?node2 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2013-0214-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-10-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-10-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2020-13848-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-35-dot-1 ?driver1 )
( has-n1-system-35-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2023-42670-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-63-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-63-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-106555-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n2-driver-3-dot-1 ?driver1 )
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )
( exploited-n1 ?node1 )
( has-n2-system-3-dot-1 ?system1 )
( has-service-up-n2 ?node2 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2023-34966-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-58-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-n1-driver-58-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2022-32742-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-51-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-n1-driver-51-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2017-12150-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-23-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-23-dot-1 ?system1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2019-10218-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-31-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-31-dot-1 ?driver1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2017-15107-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-26-dot-1 ?system1 )
( has-n1-driver-26-dot-1 ?driver1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-12969-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-67-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-67-dot-1 ?system1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-35387-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )
( has-n2-system-9-dot-1 ?system1 )
( has-n2-driver-9-dot-1 ?driver1 )
( exploited-n1 ?node1 )
( has-service-up-n2 ?node2 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2026-12725-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-66-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-66-dot-1 ?driver1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-59999-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( exploited-n1 ?node1 )
( has-n2-driver-15-dot-1 ?driver1 )
( has-service-up-n1 ?node1 )
( has-service-up-n2 ?node2 )
( has-n2-system-15-dot-1 ?system1 )
( can-ping ?node1 ?node2 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2018-10858-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-29-dot-1 ?driver1 )
( has-n1-system-29-dot-1 ?system1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2022-37966-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-52-dot-1 ?driver1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-52-dot-1 ?system1 )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2021-44141-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-47-dot-1 ?system1 )
( has-n1-driver-47-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2018-10662-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system)
:precondition
(and
( has-service-up-n3 ?node2 )
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )
( has-n3-system-8-dot-1 ?system1 )
( exploited-n1 ?node1 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2021-44142-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-48-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-48-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action connectivity-edge-between-linksys-wrt3200acm-and-pi
:parameters (?node1 - node ?node2 - node)
:precondition
(and
( has-service-up-n2 ?node2 )
( can-ping ?node1 ?node2 )
( has-service-up-n1 ?node1 )

)
:effect
(and
( has-connection-to ?node2 )

)
)

(:action attacker-exploit-cve-2013-4124-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-12-dot-1 ?driver1 )
( has-n1-system-12-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action connectivity-edge-between-linksys-wrt3200acm-and-axis-m1014
:parameters (?node1 - node ?node2 - node)
:precondition
(and
( can-ping ?node1 ?node2 )
( has-service-up-n1 ?node1 )
( has-service-up-n3 ?node2 )

)
:effect
(and
( has-connection-to ?node2 )

)
)

(:action attacker-exploit-cve-2013-4408-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-13-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-13-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2016-6255-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-21-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-21-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2018-10660-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system)
:precondition
(and
( has-service-up-n3 ?node2 )
( exploited-n1 ?node1 )
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )
( has-n3-system-6-dot-1 ?system1 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2026-59995-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )
( has-service-up-n2 ?node2 )
( has-n2-driver-11-dot-1 ?driver1 )
( has-n2-system-11-dot-1 ?system1 )
( exploited-n1 ?node1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2026-106586-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n2 ?node2 )
( can-ping ?node1 ?node2 )
( exploited-n1 ?node1 )
( has-service-up-n1 ?node1 )
( has-n2-driver-6-dot-1 ?driver1 )
( has-n2-system-6-dot-1 ?system1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2019-11072-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-32-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-32-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2023-4091-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-62-dot-1 ?driver1 )
( has-n1-system-62-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2020-25717-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-43-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-43-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2023-5568-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-65-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-65-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2011-2694-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-7-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-7-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2015-5299-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-system-15-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-driver-15-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2017-12163-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-25-dot-1 ?system1 )
( has-service-up-n1 ?node )
( has-n1-driver-25-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2026-59998-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n2-system-14-dot-1 ?system1 )
( has-n2-driver-14-dot-1 ?driver1 )
( exploited-n1 ?node1 )
( has-service-up-n2 ?node2 )
( can-ping ?node1 ?node2 )
( has-service-up-n1 ?node1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-exploit-cve-2013-0213-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-9-dot-1 ?driver1 )
( has-n1-system-9-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2019-3824-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-n1-system-34-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-34-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2018-19052-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-30-dot-1 ?driver1 )
( has-n1-system-30-dot-1 ?system1 )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2023-3961-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n1-driver-61-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-61-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2011-2522-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-driver-6-dot-1 ?driver1 )
( has-service-up-n1 ?node )
( has-n1-system-6-dot-1 ?system1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2016-6255-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( exploited-n1 ?node1 )
( has-service-up-n1 ?node1 )
( has-n3-system-2-dot-1 ?system1 )
( has-n3-driver-2-dot-1 ?driver1 )
( has-service-up-n3 ?node2 )
( can-ping ?node1 ?node2 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2026-106582-to-compromise-pi-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system ?driver1 - driver)
:precondition
(and
( has-n2-driver-4-dot-1 ?driver1 )
( has-service-up-n2 ?node2 )
( has-service-up-n1 ?node1 )
( exploited-n1 ?node1 )
( can-ping ?node1 ?node2 )
( has-n2-system-4-dot-1 ?system1 )

)
:effect
(and
( exploited-n2 ?node2 )

)
)

(:action attacker-has-access-to-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary)
:precondition
(and
( has-attacker ?atk )
( has-service-up-n1 ?node )

)
:effect
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )

)
)

(:action attacker-exploit-cve-2018-10661-to-compromise-axis-m1014-via-linksys-wrt3200acm
:parameters (?node2 - node ?node1 - node ?system1 - system)
:precondition
(and
( has-service-up-n1 ?node1 )
( can-ping ?node1 ?node2 )
( has-n3-system-7-dot-1 ?system1 )
( has-service-up-n3 ?node2 )
( exploited-n1 ?node1 )

)
:effect
(and
( exploited-n3 ?node2 )

)
)

(:action attacker-exploit-cve-2016-2125-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-service-up-n1 ?node )
( has-n1-system-20-dot-1 ?system1 )
( has-n1-driver-20-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)

(:action attacker-exploit-cve-2013-0454-to-compromise-linksys-wrt3200acm
:parameters (?node - node ?atk - adversary ?system1 - system ?driver1 - driver)
:precondition
(and
( has-service-up-n1 ?node )
( has-access-to-linksys-wrt3200acm-node ?node ?atk )
( has-n1-system-11-dot-1 ?system1 )
( has-n1-driver-11-dot-1 ?driver1 )

)
:effect
(and
( exploited-n1 ?node )

)
)


 )