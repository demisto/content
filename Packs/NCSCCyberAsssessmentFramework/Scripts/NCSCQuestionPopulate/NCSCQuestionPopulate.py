import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


question_data = {
    "AssessmentA": [{
        "name": "A1a Board Direction",  # noqa: E501
        "question": "You have effective organisational security management led at board level and articulated clearly "
                    "in corresponding policies.",  # noqa: E501
        "answers": [{
            "answer": "The security of network and information systems related to the operation  of essential functions is not discussed or reported on regularly at board-level.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Board-level discussions on the security of networks and information systems are based on partial or out-of-date information, without the benefit of expert guidance.",  # noqa: E501
            "score": 0
        }, {
            "answer": "The security of networks and information systems supporting your essential functions are not driven effectively by the direction set at board level.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Senior management or other pockets of the organisation consider themselves exempt from some policies or expect special accommodations to be made.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your organisation's approach and policy relating to the security of networks and information systems supporting the operation  of essential functions are owned and managed at board level. These are communicated, in a meaningful way, to risk management decision-makers across the organisation.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Regular board discussions on the security of network and information systems supporting the operation  of your essential function take place, based on timely and accurate information and informed by expert guidance.",  # noqa: E501
            "score": 2
        }, {
            "answer": "There is a board-level individual who has overall accountability for the security of networks and information systems and drives regular discussion at board-level.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Direction set at board level is translated into effective organisational practices that direct and control the security of the networks and information systems supporting your essential function.",  # noqa: E501
            "score": 2
        }],
        "total": 8
    }, {
        "name": "A1b Roles and Responsibilities",  # noqa: E501
        "question": "Your organisation has established roles and responsibilities for the security of networks and information systems at all levels, with clear and well-understood channels for communicating and escalating risks.",  # noqa: E501
        "answers": [{
            "answer": "Key roles are missing, left vacant, or fulfilled on an ad-hoc or informal basis.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Staff are assigned security responsibilities but without adequate authority or resources to fulfil them.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Staff are unsure what their responsibilities are for the security of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Necessary roles and responsibilities for the security of networks and information systems supporting your essential function have been identified. These are reviewed periodically to ensure they remain fit for purpose.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Appropriately capable and knowledgeable staff fill those roles and are given the time, authority, and resources to carry out their duties.",  # noqa: E501
            "score": 2
        }, {
            "answer": "There is clarity on who in your organisation has overall accountability for the security of the networks and information systems supporting your essential function.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "A1c Decision-making",  # noqa: E501
        "question": "You have senior-level accountability for the security of networks and information systems, and delegate decision-making authority appropriately and effectively. Risks to network and information systems related to the operation  of essential functions are considered in the context of other organisational risks.",  # noqa: E501
        "answers": [{
            "answer": "What should be relatively straightforward risk decisions are constantly referred up the chain, or not made.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Risks are resolved informally (or ignored) at a local level without a formal reporting mechanism when it is not appropriate.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Decision-makers are unsure of what senior management's risk appetite is, or only understand it in vague terms such as \"averse\" or \"cautious\".",  # noqa: E501
            "score": 0
        }, {
            "answer": "Organisational structure causes risk decisions to be made in isolation. (e.g. engineering and IT don't talk to each other about risk).",  # noqa: E501
            "score": 0
        }, {
            "answer": "Risk priorities are too vague to make meaningful distinctions between them. (e.g. almost all risks are rated 'medium' or 'amber').",  # noqa: E501
            "score": 0
        }, {
            "answer": "Senior management have visibility of key risk decisions made throughout the organisation.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Risk management decision-makers understand their responsibilities for making effective and timely decisions in the context of the risk appetite regarding the essential function, as set by senior management.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Risk management decision-making is delegated and escalated where necessary, across the organisation, to people who have the skills, knowledge, tools, and authority they need.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Risk management decisions are periodically reviewed to ensure their continued relevance and validity.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "A2a Risk Management Process",  # noqa: E501
        "question": "Your organisation has effective internal processes for managing risks to the security of network and information systems related to the operation of essential functions and communicating associated activities.",  # noqa: E501
        "answers": [{
            "answer": "Risk assessments are not based on a clearly defined set of threat assumptions.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Risk assessment outputs are too complex or unwieldy to be consumed by decision-makers and are not effectively communicated in a clear and timely manner.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Risk assessments for critical systems are a \"one-off\" activity (or not done at all).",  # noqa: E501
            "score": 0
        }, {
            "answer": "The security elements of projects or programmes are solely dependent on the completion of a risk management assessment without any regard to the outcomes.",  # noqa: E501
            "score": 0
        }, {
            "answer": "There is no systematic process in place to ensure that identified security risks are managed effectively.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Systems are assessed in isolation, without consideration of dependencies and interactions with other systems. (e.g. interactions between IT and OT environments).",  # noqa: E501
            "score": 0
        }, {
            "answer": "Security requirements and mitigation's are arbitrary or are applied from a control catalogue without consideration of how they contribute to the security of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Risks remain unresolved on a register for prolonged periods of time awaiting senior decision-making or resource allocation to resolve.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your organisational process ensures that security risks to networks and information systems relevant to essential functions are identified, analysed, prioritised, and managed.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your risk assessments are informed by an understanding of the vulnerabilities in the networks and information systems supporting your essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "The output from your risk management process is a clear set of security requirements that will address the risks in line with your organisational approach to security.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Significant conclusions reached in the course of your risk management process are communicated to key security decision-makers and accountable individuals.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You conduct risk assessments when significant events potentially affect the essential function, such as replacing a system or a change in the cyber security threat.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You perform threat analysis and understand how generic threats apply to your organisation.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your organisational process ensures that security risks to networks and information systems relevant to essential functions are identified, analysed, prioritised, and managed.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your approach to risk is focused on the possibility of adverse impact to your essential function, leading to a detailed understanding of how such impact might arise as a consequence of possible attacker actions and the security properties of your networks and information systems.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your risk assessments are based on a clearly understood set of threat assumptions, informed by an up-to-date understanding of security threats to your essential function and your sector.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your risk assessments are informed by an understanding of the vulnerabilities in the networks and information systems supporting your essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The output from your risk management process is a clear set of security requirements that will address the risks in line with your organisational approach to security.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Significant conclusions reached in the course of your risk management process are communicated to key security decision-makers and accountable individuals.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You conduct risk assessments when significant events potentially affect the essential function, such as replacing a system or a change in the cyber security threat.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your risk assessments are dynamic and updated in the light of relevant changes which may include technical changes to networks and information systems, change of use and new threat information.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The effectiveness of your risk management process is reviewed periodically, and improvements made as required.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You perform detailed threat analysis and understand how this applies to your organisation in the context of the threat to your sector and the wider CNI.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "A2b Assurance",  # noqa: E501
        "question": "You have gained confidence in the effectiveness of the security of your technology, people, and processes relevant to essential functions.",  # noqa: E501
        "answers": [{
            "answer": "A particular product or service is seen as a \"silver bullet\" and vendor claims are taken at face value.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Assurance methods are applied without appreciation of their strengths and limitations, such as the risks of penetration testing in operational environments.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Assurance is assumed because there have been no known problems to date.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You validate that the security measures in place to protect the networks and information systems are effective and remain effective for the lifetime over which they are needed.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You understand the assurance methods available to you and choose appropriate methods to gain confidence in the security of essential functions.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your confidence in the security as it relates to your technology, people, and processes can be justified to, and verified by, a third party.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Security deficiencies uncovered by assurance activities are assessed, prioritised and remedied when necessary in a timely and effective way.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The methods used for assurance are reviewed to ensure they are working as intended and remain the most appropriate method to use.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "A3a Asset Management",  # noqa: E501
        "question": "Everything required to deliver, maintain or support networks and information systems necessary for the operation of essential functions is determined and understood. This includes data, people and systems, as well as any supporting infrastructure (such as power or cooling).",  # noqa: E501
        "answers": [{
            "answer": "Inventories of assets relevant to the essential function are incomplete, non-existent, or inadequately detailed.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Only certain domains or types of asset are documented and understood. Dependencies between assets are not understood (such as the dependencies between IT and OT).",  # noqa: E501
            "score": 0
        }, {
            "answer": "Information assets, which could include personally identifiable information or other sensitive information, are stored for long periods of time with no clear business need or retention policy.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Knowledge critical to the management, operation, or recovery of essential functions is held by one or two key individuals with no succession plan.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Asset inventories are neglected and out of date.",  # noqa: E501
            "score": 0
        }, {
            "answer": "All assets relevant to the secure operation of essential functions are identified and inventoried (at a suitable level of detail).  The inventory is kept up-to-date.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Dependencies on supporting infrastructure (e.g. power, cooling etc) are recognised and recorded.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have prioritised your assets according to their importance to the operation of the essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have assigned responsibility for managing physical assets.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Assets relevant to essential functions are managed with cyber security in mind throughout their lifecycle, from creation through to eventual decommissioning or disposal.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "A4a Supply Chain",  # noqa: E501
        "question": "The organisation understands and manages security risks to networks and information systems supporting the operation of essential functions that arise as a result of dependencies on external suppliers. This includes ensuring that appropriate measures are employed where third party services are used.",  # noqa: E501
        "answers": [{
            "answer": "You do not know what data belonging to you is held by suppliers, or how it is managed.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Elements of the supply chain for essential functions are subcontracted and you have little or no visibility of the sub-contractors.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Relevant contracts do not have security requirements.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Suppliers have access to systems that provide your essential function that is unrestricted, not monitored or bypasses your own security controls.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You understand the general risks suppliers may pose to your essential functions.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You know the extent of your supply chain for essential functions, including sub-contractors.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You engage with suppliers about security, and you set and communicate security requirements in contracts.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You are aware of all third-party connections and have assurance that they meet your organisation's security requirements.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your approach to security incident management considers incidents that might arise in your supply chain.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have confidence that information shared with suppliers that is necessary for the operation of your essential function is appropriately protected from well-known attacks and known vulnerabilities.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have a deep understanding of your supply chain, including sub-contractors and the wider risks it faces. You consider factors such as supplier's partnerships, competitors, nationality and other organisations with which they sub-contract. This informs your risk assessment and procurement processes.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your approach to supply chain risk management considers the risks to your essential functions arising from supply chain subversion by capable and well-resourced attackers.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have confidence that information shared with suppliers that is essential to the operation of your function is appropriately protected from sophisticated attacks.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You can clearly express the security needs you place on suppliers in ways that are mutually understood and are laid in contracts. There is a clear and documented shared-responsibility model.",  # noqa: E501
            "score": 2
        }, {
            "answer": "All network connections and data sharing with third parties is managed effectively and proportionately.",  # noqa: E501
            "score": 2
        }, {
            "answer": "When appropriate, your incident management process and that of your suppliers provide mutual support in the resolution of incidents.",  # noqa: E501
            "score": 2
        }]
    }],
    "AssessmentB": [{
        "name": "B1a Policy and Process Development",  # noqa: E501
        "question": "You have developed and continue to improve a set of cyber security and resilience policies and processes that manage and mitigate the risk of adverse impact on the essential function.",  # noqa: E501
        "answers": [{
            "answer": "Your policies and processes are absent or incomplete.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Policies and processes are not applied universally or consistently.",  # noqa: E501
            "score": 0
        }, {
            "answer": "People often or routinely circumvent policies and processes to achieve business objectives.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your organisation's security governance and risk management approach has no bearing on your policies and processes.",  # noqa: E501
            "score": 0
        }, {
            "answer": "System security is totally reliant on users' careful and consistent application of manual security processes.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Policies and processes have not been reviewed in response to major changes (e.g. technology or regulatory framework), or within a suitable period.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Policies and processes are not readily available to staff, too detailed to remember, or too hard to understand.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your policies and processes document your overarching security governance and risk management approach, technical security practice and specific regulatory compliance.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You review and update policies and processes in response to major cyber security incidents.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You fully document your overarching security governance and risk management approach, technical security practice and specific regulatory compliance. Cyber security is integrated and embedded throughout these policies and processes and key performance indicators are reported to your executive management.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your organisation's policies and processes are developed to be practical, usable and appropriate for your essential function and your technologies.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Policies and processes that rely on user behaviour are practical, appropriate and achievable.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You review and update policies and processes at suitably regular intervals to ensure they remain relevant. This is in addition to reviews following a major cyber security incident.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Any changes to the essential function or the threat it faces triggers a review of policies and processes.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your systems are designed so that they remain secure even when user security policies and processes are not always followed.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B1b Policy and Process Implementation",  # noqa: E501
        "question": "You have successfully implemented your security policies and processes and can demonstrate the security benefits achieved.",  # noqa: E501
        "answers": [{
            "answer": "Policies and processes are ignored or only partially followed.",  # noqa: E501
            "score": 0
        }, {
            "answer": "The reliance on your policies and processes is not well understood.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Staff are unaware of their responsibilities under your policies and processes.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not attempt to detect breaches of policies and processes.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Policies and processes lack integration with other organisational policies and processes.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your policies and processes are not well communicated across your organisation.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Most of your policies and processes are followed and their application is monitored.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your policies and processes are integrated with other organisational policies and processes, including HR assessments of individuals' trustworthiness.",  # noqa: E501
            "score": 1
        }, {
            "answer": "All staff are aware of their responsibilities under your policies and processes.",  # noqa: E501
            "score": 1
        }, {
            "answer": "All breaches of policies and processes with the potential to adversely impact the essential function are fully investigated. Other breaches are tracked, assessed for trends and action is taken to understand and address.",  # noqa: E501
            "score": 1
        }, {
            "answer": "All your policies and processes are followed, their correct application and security effectiveness is evaluated.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your policies and processes are integrated with other organisational policies and processes, including HR assessments of individuals' trustworthiness.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your policies and processes are effectively and appropriately communicated across all levels of the organisation resulting in good staff awareness of their responsibilities.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Appropriate action is taken to address all breaches of policies and processes with potential to adversely impact the essential function including aggregated breaches.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B2a Identity Verification, Authentication and Authorisation",  # noqa: E501
        "question": "You robustly verify, authenticate and authorise access to the networks and information systems supporting your essential function.",  # noqa: E501
        "answers": [{
            "answer": "Authorised users with access to networks or information systems on which your essential function depends cannot be individually identified.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Unauthorised individuals or devices can access your networks or information systems on which your essential function depends.",  # noqa: E501
            "score": 0
        }, {
            "answer": "User access is not limited to the minimum necessary.",  # noqa: E501
            "score": 0
        }, {
            "answer": "All authorised users with access to networks or information systems on which your essential function depends are individually identified and authenticated.",  # noqa: E501
            "score": 1
        }, {
            "answer": "User access to essential function networks and information systems is limited to the minimum necessary.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You use additional authentication mechanisms, such as two-factor or hardware-backed certificates, for privileged access to sensitive systems such as operational technology.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You individually authenticate and authorise all remote user access to all your networks and information systems that support your essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "The list of users with access to essential function networks and systems is reviewed on a regular basis at least annually.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Only authorised and individually authenticated users can physically access and logically connect to your networks or information systems on which your essential function depends.",  # noqa: E501
            "score": 2
        }, {
            "answer": "User access to all your networks and information systems supporting the essential function is limited to the minimum necessary.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You use additional authentication mechanisms, such as two-factor or hardware-backed certificates, for privileged access to all systems that operate or support your essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You use additional authentication mechanisms, such as two-factor or hardware-backed certificates, when you individually authenticate and authorise all remote user access to all your networks and information systems that support your essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The list of users with access to networks and systems supporting and delivering the essential function is reviewed on a regular basis, at least every six months.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B2b Device Management",  # noqa: E501
        "question": "You fully know and have trust in the devices that are used to access your networks, information systems and data that support your essential function.",  # noqa: E501
        "answers": [{
            "answer": "Users can connect to your essential function's networks using devices that are not corporately managed.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Privileged users can perform administrative functions from devices that are not corporately managed.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have not gained assurance in the security of any third-party devices or networks connected to your systems.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Physically connecting a device to your network gives that device access without device or user authentication",  # noqa: E501
            "score": 0
        }, {
            "answer": "Only corporately owned and managed devices can access your essential function's networks and information systems.",  # noqa: E501
            "score": 1
        }, {
            "answer": "All privileged access occurs from corporately management devices dedicated to management functions.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have sought to understand the security properties of third-party devices and networks before they can be connected to your systems. You have taken appropriate steps to mitigate any risks identified.",  # noqa: E501
            "score": 1
        }, {
            "answer": "The act of connecting to a network port or cable does not grant access to any systems.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You are able to detect unknown devices being connected to your network and investigate such incidents.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Dedicated devices are used for privileged actions (such as administration or accessing the essential function's network and information systems). These devices are not used for directly browsing the web or accessing email.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You either obtain independent and professional assurance of the security of third-party devices or networks before they connect to your systems, or you only allow third-party devices or networks dedicated to supporting your systems to connect.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You perform certificate-based device identity management and only allow known devices to access systems necessary for the operation of your essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You perform regular scans to detect unknown devices and investigate any findings.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B2c Privileged User Management",  # noqa: E501
        "question": "You closely manage privileged user access to networks and information systems supporting the essential function.",  # noqa: E501
        "answers": [{
            "answer": "The identities of the individuals with privileged access to your essential function systems (infrastructure, platforms, software, configuration, etc) are not known or not managed.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Privileged user access to your essential function systems is via weak authentication mechanisms (e.g. only simple passwords).",  # noqa: E501
            "score": 0
        }, {
            "answer": "The list of privileged users has not been reviewed recently (e.g. within the last 12 months).",  # noqa: E501
            "score": 0
        }, {
            "answer": "Privileged user access is granted on a system-wide basis rather than by role or function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Privileged user access to your essential function is via generic, shared or default name accounts.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Where there are \"always on\" terminals which can perform privileged actions (such as in a control room), there are no additional controls (e.g. physical controls) to ensure access is appropriately restricted.",  # noqa: E501
            "score": 0
        }, {
            "answer": "There is no logical separation between roles that an individual may have and hence the actions they perform. (e.g. access to corporate email and privilege user actions).",  # noqa: E501
            "score": 0
        }, {
            "answer": "Privileged user access requires additional validation, but this does not use a strong form of authentication (e.g. two-factor, hardware authentication or additional real-time security monitoring).",  # noqa: E501
            "score": 1
        }, {
            "answer": "The identities of the individuals with privileged access to your essential function systems (infrastructure, platforms, software, configuration, etc) are known and managed. This includes third parties.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Activity by privileged users is routinely reviewed and validated. (e.g. at least annually).",  # noqa: E501
            "score": 1
        }, {
            "answer": "Privileged users are only granted specific privileged permissions which are essential to their business role or function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Privileged user access to your essential function systems is carried out from dedicated separate accounts that are closely monitored and managed.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The issuing of temporary, time-bound rights for privileged user access and external third-party support access is either in place or you are migrating to an access control solution that supports this functionality.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Privileged user access rights are regularly reviewed and always updated as part of your joiners, movers and leavers process.",  # noqa: E501
            "score": 2
        }, {
            "answer": "All privileged user access to your networks and information systems requires strong authentication, such as two-factor, hardware authentication, or additional real-time security monitoring.",  # noqa: E501
            "score": 2
        }, {
            "answer": "All privileged user activity is routinely reviewed, validated and recorded for offline analysis and investigation.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B2d Identity and Access Management",  # noqa: E501
        "question": "You assure good management and maintenance of identity and access control for your networks and information systems supporting the essential function.",  # noqa: E501
        "answers": [{
            "answer": "Greater rights are granted to users than necessary.",  # noqa: E501
            "score": 0
        }, {
            "answer": "User rights are granted without validation of their identity and requirement for access.",  # noqa: E501
            "score": 0
        }, {
            "answer": "User rights are not reviewed when they move jobs.",  # noqa: E501
            "score": 0
        }, {
            "answer": "User rights remain active when people leave your organisation.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You follow a robust procedure to verify each user and issue the minimum required access rights.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You regularly review access rights and those no longer needed are revoked.",  # noqa: E501
            "score": 1
        }, {
            "answer": "User permissions are reviewed when people change roles via your joiners, leavers and movers process.",  # noqa: E501
            "score": 1
        }, {
            "answer": "All user access is logged and monitored.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your procedure to verify each user and issue the minimum required access rights is robust and regularly audited.",  # noqa: E501
            "score": 2
        }, {
            "answer": "User permissions are reviewed both when people change roles via your joiners, leavers and movers process and at regular intervals - at least annually.",  # noqa: E501
            "score": 2
        }, {
            "answer": "All user access is logged and monitored.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You regularly review access logs and correlate this data with other access records and expected activity.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Attempts by unauthorised users to connect to your systems are alerted, promptly assessed and investigated.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B3a Understanding Data",  # noqa: E501
        "question": "You have a good understanding of data important to the operation of the essential function, where it is stored, where it travels and how unavailability or unauthorised access, modification or deletion would adversely impact the essential function. This also applies to third parties storing or accessing data important to the operation of essential functions.",  # noqa: E501
        "answers": [{
            "answer": "You have incomplete knowledge of what data is used by and produced in the operation of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have not identified the important data on which your essential function relies.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have not identified who has access to data important to the operation of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have not clearly articulated the impact of data compromise or inaccessibility.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have identified and catalogued all the data important to the operation of the essential function, or that would assist an attacker.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have identified and catalogued who has access to the data important to the operation of the essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You periodically review location, transmission, quantity and quality of data important to the operation of the essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have identified all mobile devices and media that hold data important to the operation of the essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You understand and document the impact on your essential function of all relevant scenarios, including unauthorised access, modification or deletion, or when authorised users are unable to appropriately access this data.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You occasionally validate these documented impact statements.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have identified and catalogued all the data important to the operation of the essential function, or that would assist an attacker.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have identified and catalogued all the data important to the operation of the essential function, or that would assist an attacker.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You maintain a current understanding of the location, quantity and quality of data important to the operation of the essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You take steps to remove or minimise unnecessary copies or unneeded historic data.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have identified all mobile devices and media that may hold data important to the operation of the essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You maintain a current understanding of the data links used to transmit data that is important to your essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You understand the context, limitations and dependencies of your important data.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You understand and document the impact on your essential function of all relevant scenarios, including unauthorised data access, modification or deletion, or when authorised users are unable to appropriately access this data.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You validate these documented impact statements regularly, at least annually.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B3b Data in Transit",  # noqa: E501
        "question": "You have protected the transit of data important to the operation of the essential function. This includes the transfer of data to third parties. ",  # noqa: E501
        "answers": [{
            "answer": "You do not know what all your data links are, or which carry data important to the operation of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Data important to the operation of the essential function travels without technical protection over non-trusted or openly accessible carriers.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Critical data paths that could fail, be jammed, be overloaded, etc. have no alternative path.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have identified and protected (effectively and proportionately) all the data links that carry data important to the operation of your essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You apply appropriate technical means (e.g. cryptography) to protect data that travels over non-trusted or openly accessible carriers, but you have limited or no confidence in the robustness of the protection applied.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have identified and protected (effectively and proportionately) all the data links that carry data important to the operation of your essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You apply appropriate physical or technical means to protect data that travels over non-trusted or openly accessible carriers, with justified confidence in the robustness of the protection applied.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Suitable alternative transmission paths are available where there is a significant risk of impact on the operation of the essential function due to resource limitation (e.g. transmission equipment or function failure, or important data being blocked or jammed).",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B3c Stored Data",  # noqa: E501
        "question": "You have protected stored data important to the operation of the essential function.",  # noqa: E501
        "answers": [{
            "answer": "You have no, or limited, knowledge of where data important to the operation of the essential function is stored.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have not protected vulnerable stored data important to the operation of the essential function in a suitable way.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Backups are incomplete, untested, not adequately secured or could be inaccessible in a disaster recovery or business continuity situation.",  # noqa: E501
            "score": 0
        }, {
            "answer": "All copies of data important to the operation of your essential function are necessary. Where this important data is transferred to less secure systems, the data is provided with limited detail and/or as a read-only copy.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have applied suitable physical or technical means to protect this important stored data from unauthorised access, modification or deletion.",  # noqa: E501
            "score": 1
        }, {
            "answer": "If cryptographic protections are used, you apply suitable technical and procedural means, but you have limited or no confidence in the robustness of the protection applied.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have suitable, secured backups of data to allow the operation of the essential function to continue should the original data not be available. This may include off-line or segregated backups, or appropriate alternative forms such as paper copies.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have only necessary copies of this data. Where data is transferred to less secure systems, the data is provided with limited detail and/or as a read-only copy.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have applied suitable physical or technical means to protect this important stored data from unauthorised access, modification or deletion.",  # noqa: E501
            "score": 2
        }, {
            "answer": "If cryptographic protections are used you apply suitable technical and procedural means, and you have justified confidence in the robustness of the protection applied.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have suitable, secured backups of data to allow the operation of the essential function to continue should the original data not be available. This may include off-line or segregated backups, or appropriate alternative forms such as paper copies.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Necessary historic or archive data is suitably secured in storage.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B3d Mobile Data",  # noqa: E501
        "question": "You have protected data important to the operation of the essential function on mobile devices.",  # noqa: E501
        "answers": [{
            "answer": "You don't know which mobile devices may hold data important to the operation of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You allow data important to the operation of the essential function to be stored on devices not managed by your organisation, or to at least equivalent standard.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Data on mobile devices is not technically secured, or only some is secured.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You know which mobile devices hold data important to the operation of the essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Data important to the operation of the essential function is only stored on mobile devices with at least equivalent security standard to your organisation.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Data on mobile devices is technically secured.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Mobile devices that hold data that is important to the operation of the essential function are catalogued, are under your organisation's control and configured according to best practice for the platform, with appropriate technical and procedural policies in place.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your organisation can remotely wipe all mobile devices holding data important to the operation of essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have minimised this data on these mobile devices. Some data may be automatically deleted off mobile devices after a certain period.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B3e Media Equipment Sanitisation",  # noqa: E501
        "question": "You appropriately sanitise media and equipment holding data important to the operation of the essential function",  # noqa: E501
        "answers": [{
            "answer": "Some or all devices, equipment or removable media that hold data important to the operation of the essential function are disposed of without sanitisation of that data.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You catalogue and track all devices that contain data important to the operation of the essential function (whether a specific storage device or one with integral storage).",  # noqa: E501
            "score": 2
        }, {
            "answer": "All data important to the operation of the essential function is sanitised from all devices, equipment or removable media before disposal.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B4a Secure by Design",  # noqa: E501
        "question": "You design security into the network and information systems that support the operation of essential functions. You minimise their attack surface and ensure that the operation of the essential function should not be impacted by the exploitation of any single vulnerability",  # noqa: E501
        "answers": [{
            "answer": "Systems essential to the operation of the essential function are not appropriately segregated from other systems.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Internet access is available from operational systems.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Data flows between the essential function's operational systems and other systems are complex, making it hard to discriminate between legitimate and illegitimate/malicious traffic.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Remote or third party accesses circumvent some network controls to gain more direct access to operational systems of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You employ appropriate expertise to design network and information systems.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You design strong boundary defences where your networks and information systems interface with other organisations or the world at large.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You design simple data flows between your networks and information systems and any external interface to enable effective monitoring.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You design to make network and information system recovery simple.",  # noqa: E501
            "score": 1
        }, {
            "answer": "All inputs to operational systems are checked and validated at the network boundary where possible, or additional monitoring is in place for content-based attacks.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You employ appropriate expertise to design network and information systems.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your networks and information systems are segregated into appropriate security zones, e.g. operational systems for the essential function are segregated in a highly trusted, more secure zone.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The networks and information systems supporting your essential function are designed to have simple data flows between components to support effective security monitoring.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The networks and information systems supporting your essential function are designed to be easy to recover.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Content-based attacks are mitigated for all inputs to operational systems that affect the essential function (e.g. via transformation and inspection).",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B4b Secure Configuration",  # noqa: E501
        "question": "You securely configure the network and information systems that support the operation of essential functions.",  # noqa: E501
        "answers": [{
            "answer": "You haven't identified the assets that need to be carefully configured to maintain the security of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Policies relating to the security of operating system builds or configuration are not applied consistently across your network and information systems relating to your essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Configuration details are not recorded or lack enough information to be able to rebuild the system or device.",  # noqa: E501
            "score": 0
        }, {
            "answer": "The recording of security changes or adjustments that effect your essential function is lacking or inconsistent.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have identified and documented the assets that need to be carefully configured to maintain the security of the essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Secure platform and device builds are used across the estate.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Consistent, secure and minimal system and device configurations are applied across the same types of environment.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Changes and adjustments to security configuration at security boundaries with the networks and information systems supporting your essential function are approved and documented.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You verify software before installation is permitted.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have identified, documented and actively manage (e.g. maintain security configurations, patching, updating according to good practice) the assets that need to be carefully configured to maintain the security of the essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "All platforms conform to your secure, defined baseline build, or the latest known good configuration version for that environment. ",  # noqa: E501
            "score": 2
        }, {
            "answer": "You closely and effectively manage changes in your environment, ensuring that network and system configurations are secure and documented.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You regularly review and validate that your network and information systems have the expected, secured settings and configuration.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Only permitted software can be installed and standard users cannot change settings that would impact security or business operation.",  # noqa: E501
            "score": 2
        }, {
            "answer": "If automated decision-making technologies are in use, their operation is well understood, and decisions can be replicated.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B4c Secure Management",  # noqa: E501
        "question": "You manage your organisation's network and information systems that support the operation of essential functions to enable and maintain security.",  # noqa: E501
        "answers": [{
            "answer": "Essential function networks and systems are administered or maintained using non-dedicated devices.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not have good or current technical documentation of your networks and information systems.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your systems and devices supporting the operation of the essential function are only administered or maintained by authorised privileged users from dedicated devices.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Technical knowledge about networks and information systems, such as documentation and network diagrams, is regularly reviewed and updated.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You prevent, detect and remove malware or unauthorised software. You use technical, procedural and physical measures as necessary.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your systems and devices supporting the operation of the essential function are only administered or maintained by authorised privileged users from dedicated devices that are technically segregated and secured to the same level as the networks and systems being maintained.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You regularly review and update technical knowledge about networks and information systems, such as documentation and network diagrams, and ensure they are securely stored.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You prevent, detect and remove malware or unauthorised software. You use technical, procedural and physical measures as necessary.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B4d Vulnerability Management",  # noqa: E501
        "question": "You manage known vulnerabilities in your network and information systems to prevent adverse impact on the essential function.",  # noqa: E501
        "answers": [{
            "answer": "You do not understand the exposure of your essential function to publicly-known vulnerabilities.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not mitigate externally-exposed vulnerabilities promptly.",  # noqa: E501
            "score": 0
        }, {
            "answer": "There are no means to check data or software imports for malware.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have not recently tested to verify your understanding of the vulnerabilities of the networks and information systems that support your essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have not suitably mitigated systems or software that is no longer supported. ",  # noqa: E501
            "score": 0
        }, {
            "answer": "You are not pursuing replacement for unsupported systems or software.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You maintain a current understanding of the exposure of your essential function to publicly-known vulnerabilities.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Announced vulnerabilities for all software packages, network equipment and operating systems used to support your essential function are tracked, prioritised and externally-exposed vulnerabilities are mitigated (e.g. by patching) promptly.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Some vulnerabilities that are not externally exposed have temporary mitigations for an extended period.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have temporary mitigations for unsupported systems and software while pursuing migration to supported technology.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You regularly test to fully understand the vulnerabilities of the networks and information systems that support the operation of your essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You maintain a current understanding of the exposure of your essential function to publicly-known vulnerabilities.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Announced vulnerabilities for all software packages, network equipment and operating systems used to support the operation of your essential function are tracked, prioritised and mitigated (e.g. by patching) promptly.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You regularly test to fully understand the vulnerabilities of the networks and information systems that support the operation of your essential function and verify this understanding with third-party testing.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You maximise the use of supported software, firmware and hardware in your networks and information systems supporting your essential function.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B5a Resilience Preparation",  # noqa: E501
        "question": "You are prepared to restore the operation of your essential function following adverse impact.",  # noqa: E501
        "answers": [{
            "answer": "You have limited understanding of all the elements that are required to restore operation of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have not completed business continuity and/or disaster recovery plans for your essential function's networks, information systems and their dependencies.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have not fully assessed the practical implementation of your disaster recovery plans.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You know all networks, information systems and underlying technologies that are necessary to restore the operation of the essential function and understand their interdependence.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You know the order in which systems need to be recovered to efficiently and effectively restore the operation of the essential function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have business continuity and disaster recovery plans that have been tested for practicality, effectiveness and completeness. Appropriate use is made of different test methods, e.g. manual fail-over, table-top exercises, or red-teaming.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You use your security awareness and threat intelligence sources, to make immediate and potentially temporary security changes in response to new threats, e.g. a widespread outbreak of very damaging malware.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B5b Design for Resilience",  # noqa: E501
        "question": "You design the network and information systems supporting your essential function to be resilient to cyber security incidents. Systems are appropriately segregated and resource limitations are mitigated.",  # noqa: E501
        "answers": [{
            "answer": "Operational networks and systems are not appropriately segregated.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Internet services, such as browsing and email, are accessible from essential  operational systems supporting the essential function",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not understand or lack plans to mitigate all resource limitations that could adversely affect your essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Operational systems that support the operation of the essential function are logically separated from your business systems, e.g. they reside on the same network as the rest of the organisation, but within a DMZ. Internet access is not available from operational systems.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Resource limitations (e.g. network bandwidth, single network paths) have been identified but not fully mitigated.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Operational systems that support the operation of the essential function are segregated from other business and external systems by appropriate technical and physical means, e.g. separate network and system infrastructure with independent user administration. Internet services are not accessible from operational systems.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have identified and mitigated all resource limitations, e.g. bandwidth limitations and single network paths.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have identified and mitigated any geographical constraints or weaknesses. (e.g. systems that your essential function depends upon are replicated in another location, important network connectivity has alternative physical paths and service providers).",  # noqa: E501
            "score": 2
        }, {
            "answer": "You review and update assessments of dependencies, resource and geographical limitations and mitigation's when necessary.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B5c Backups",  # noqa: E501
        "question": "You hold accessible and secured current backups of data and information needed to recover operation of your essential function",  # noqa: E501
        "answers": [{
            "answer": "Backup coverage is incomplete in coverage and would be inadequate to restore operation of your essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Backups are not frequent enough for the operation of your essential function to be restored within a suitable time-frame.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have appropriately secured backups (including data, configuration information, software, equipment, processes and key roles or knowledge). These backups will be accessible to recover from an extreme event.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You routinely test backups to ensure that the backup process functions correctly and the backups are usable.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your comprehensive, automatic and tested technical and procedural backups are secured at centrally accessible or secondary sites to recover from an extreme event.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Key roles are duplicated, and operational delivery knowledge is shared with all individuals involved in the operations and recovery of the essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Backups of all important data and information needed to recover the essential function are made, tested, documented and routinely reviewed.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B6a Cyber Security Culture",  # noqa: E501
        "question": "You develop and pursue a positive cyber security culture.",  # noqa: E501
        "answers": [{
            "answer": "People in your organisation don't understand what they contribute to the cyber security of the essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "People in your organisation don't know how to raise a concern about cyber security.",  # noqa: E501
            "score": 0
        }, {
            "answer": "People believe that reporting issues may get them into trouble.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your organisation's approach to cyber security is perceived by staff as hindering the business of the organisation.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your executive management understand and widely communicate the importance of a positive cyber security culture. Positive attitudes, behaviours and expectations are described for your organisation.",  # noqa: E501
            "score": 1
        }, {
            "answer": "All people in your organisation understand the contribution they make to the essential function's cyber security.",  # noqa: E501
            "score": 1
        }, {
            "answer": "All individuals in your organisation know who to contact and where to access more information about cyber security. They know how to raise a cyber security issue.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your executive management clearly and effectively communicates the organisation's cyber security priorities and objectives to all staff. Your organisation displays positive cyber security attitudes, behaviours and expectations.",  # noqa: E501
            "score": 2
        }, {
            "answer": "People in your organisation raising potential cyber security incidents and issues are treated positively.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Individuals at all levels in your organisation routinely report concerns or issues about cyber security and are recognised for their contribution to keeping the organisation secure.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your management is seen to be committed to and actively involved in cyber security.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your organisation communicates openly about cyber security, with any concern being taken seriously.",  # noqa: E501
            "score": 2
        }, {
            "answer": "People across your organisation participate in cyber security activities and improvements, building joint ownership and bringing knowledge of their area of expertise.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "B6b Cyber Security Training",  # noqa: E501
        "question": "The people who support the operation of your essential function are appropriately trained in cyber security. A range of approaches to cyber security training, awareness and communications are employed.",  # noqa: E501
        "answers": [{
            "answer": "There are teams who operate and support your essential function that lack any cyber security training.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Cyber security training is restricted to specific roles in your organisation.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Cyber security training records for your organisation are lacking or incomplete.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have defined appropriate cyber security training and awareness activities for all roles in your organisation, from executives to the most junior roles.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You use a range of teaching and communication techniques for cyber security training and awareness to reach the widest audience effectively.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Cyber security information is easily available.",  # noqa: E501
            "score": 1
        }, {
            "answer": "All people in your organisation, from the most senior to the most junior, follow appropriate cyber security training paths.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Each individual's cyber security training is tracked and refreshed at suitable intervals.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You routinely evaluate your cyber security training and awareness activities to ensure they reach the widest audience and are effective.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You make cyber security information and good practice guidance easily accessible, widely available and you know it is referenced and used within your organisation.",  # noqa: E501
            "score": 2
        }]
    }],
    "AssessmentC": [{
        "name": "C1a Monitoring Coverage",  # noqa: E501
        "question": "The data sources that you include in your monitoring allow for timely identification of security events which might affect the operation of your essential function.",  # noqa: E501
        "answers": [{
            "answer": "Data relating to the security and operation of your essential functions is not collected.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not confidently detect the presence or absence of Indicators of Compromise (IoCs) on your essential functions, such as known malicious command and control signatures (e.g. because applying the indicator is difficult or your logging data is not sufficiently detailed).",  # noqa: E501
            "score": 0
        }, {
            "answer": "You are not able to audit the activities of users in relation to your essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not capture any traffic crossing your network boundary including as a minimum IP connections.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Data relating to the security and operation of some areas of your essential functions is collected.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You easily detect the presence or absence of IoCs on your essential function, such as known malicious command and control signatures.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Some user monitoring is done, but not covering a fully agreed list of suspicious or undesirable behaviour.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You monitor traffic crossing your network boundary (including IP address connections as a minimum).",  # noqa: E501
            "score": 1
        }, {
            "answer": "Monitoring is based on an understanding of your networks, common cyber attack methods and what you need awareness of in order to detect potential security incidents that could affect the operation of your essential function. (e.g. presence of malware, malicious emails, user policy violations). ",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your monitoring data provides enough detail to reliably detect security incidents that could affect the operation of your essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You easily detect the presence or absence of IoCs on your essential functions, such as known malicious command and control signatures.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Extensive monitoring of user activity in relation to the operation of essential functions enables you to detect policy violations and an agreed list of suspicious or undesirable behaviour.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have extensive monitoring coverage that includes host-based monitoring and network gateways.",  # noqa: E501
            "score": 2
        }, {
            "answer": "All new systems are considered as potential monitoring data sources to maintain a comprehensive monitoring capability.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "C1b Securing Logs",  # noqa: E501
        "question": "You hold logging data securely and grant read access only to accounts with business need. No employee should ever need to modify or delete logging data within an agreed retention period, after which it should be deleted.",  # noqa: E501
        "answers": [{
            "answer": "It is possible for logging data to be easily edited or deleted by unauthorised users or malicious attackers.",  # noqa: E501
            "score": 0
        }, {
            "answer": "There is no controlled list of who can view and query logging information.",  # noqa: E501
            "score": 0
        }, {
            "answer": "There is no monitoring of the access to logging data.",  # noqa: E501
            "score": 0
        }, {
            "answer": "There is no policy for accessing logging data.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Logging is not synchronised, using an accurate common time source.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Only authorised staff can view logging data for investigations.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Privileged users can view logging information.",  # noqa: E501
            "score": 1
        }, {
            "answer": "There is some monitoring of access to logging data. (e.g. copying, deleting or modification, or even viewing.)",  # noqa: E501
            "score": 1
        }, {
            "answer": "The integrity of logging data is protected, or any modification is detected and attributed.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The logging architecture has mechanisms, processes and procedures to ensure that it can protect itself from threats comparable to those it is trying to identify. This includes protecting the function itself, and the data within it.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Log data analysis and normalisation is only performed on copies of the data keeping the master copy unaltered.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Logging datasets are synchronised, using an accurate common time source, so separate datasets can be correlated in different ways.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Access to logging data is limited to those with business need and no others.",  # noqa: E501
            "score": 2
        }, {
            "answer": "All actions involving all logging data (e.g. copying, deleting or modification, or even viewing) can be traced back to a unique user.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Legitimate reasons for accessing logging data are given in use policies.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "C1c Generating Alerts",  # noqa: E501
        "question": "Evidence of potential security incidents contained in your monitoring data is reliably identified and triggers alerts.",  # noqa: E501
        "answers": [{
            "answer": "Alerts from third party security software is not investigated e.g. Anti-Virus (AV) providers.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Logs are distributed across devices with no easy way to access them other than manual login or physical action.",  # noqa: E501
            "score": 0
        }, {
            "answer": "The resolution of alerts to a network asset or system is not performed.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Security alerts relating to essential functions are not prioritised.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Logs are reviewed infrequently.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Alerts from third party security software are investigated, and action taken.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Some logging datasets can be easily queried with search tools to aid investigations.",  # noqa: E501
            "score": 1
        }, {
            "answer": "The resolution of alerts to a network asset or system is performed regularly.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Security alerts relating to some essential functions are prioritised.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Logs are reviewed at regular intervals.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Logging data is enriched with other network knowledge and data when investigating certain suspicious activity or alerts.",  # noqa: E501
            "score": 2
        }, {
            "answer": "A wide range of signatures and indicators of compromise are used for investigations of suspicious activity and alerts.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Alerts can be easily resolved to network assets using knowledge of networks and systems.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Security alerts relating to all essential functions are prioritised and this information is used to support incident management.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Logs are reviewed almost continuously, in real time.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Alerts are tested to ensure that they are generated reliably and that it is possible to distinguish genuine security incidents from false alarms.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "C1d Identifying Security Incidents",  # noqa: E501
        "question": "You contextualise alerts with knowledge of the threat and your systems, to identify those security incidents that require some form of response.",  # noqa: E501
        "answers": [{
            "answer": "Your organisation has no sources of threat intelligence.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not apply updates in a timely way, after receiving them. (e.g. AV signature updates, other threat signatures or Indicators of Compromise (IoCs)).",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not receive signature updates for all protective technologies such as AV and IDS or other software in use.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not evaluate the usefulness of your threat intelligence or share feedback with providers or other users.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your organisation uses some threat intelligence services, but you don't choose providers specifically because of your business needs, or specific threats in your sector (e.g. sector-based infoshare, ICS software vendors, anti-virus providers, specialist threat intel firms).",  # noqa: E501
            "score": 1
        }, {
            "answer": "You receive updates for all your signature based protective technologies (e.g. AV, IDS).",  # noqa: E501
            "score": 1
        }, {
            "answer": "You apply some updates, signatures and IoCs in a timely way.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You know how effective your threat intelligence is (e.g. by tracking how threat intelligence helps you identify security problems).",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have selected threat intelligence feeds using risk-based and threat-informed decisions based on your business needs and sector (e.g. vendor reporting and patching, strong anti-virus providers, sector and community-based infoshare).",  # noqa: E501
            "score": 2
        }, {
            "answer": "You apply all new signatures and IoCs within a reasonable (risk-based) time of receiving them.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You receive signature updates for all your protective technologies (e.g. AV, IDS).",  # noqa: E501
            "score": 2
        }, {
            "answer": "You track the effectiveness of your intelligence feeds and actively share feedback on the usefulness of IoCs and any other indicators with the threat community (e.g. sector partners, threat intelligence providers, government agencies).",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "C1e  Monitoring Tools and Skills",  # noqa: E501
        "question": "Monitoring staff skills, tools and roles, including any that are outsourced, should reflect governance and reporting requirements, expected threats and the complexities of the network or system data they need to use. Monitoring staff have knowledge of the essential functions they need to protect.",  # noqa: E501
        "answers": [{
            "answer": "There are no staff who perform a monitoring function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Monitoring staff do not have the correct specialist skills.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Monitoring staff are not capable of reporting against governance requirements. Monitoring staff lack the skills to successfully perform any part of the defined workflow.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Monitoring tools are only able to make use of a fraction of logging data being collected.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Monitoring tools cannot be configured to make use of new logging streams, as they come online.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Monitoring staff have a lack of awareness of the essential functions the organisation provides, what assets relate to those functions and hence the importance of the logging data and security events.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Monitoring staff have some investigative skills and a basic understanding of the data they need to work with.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Monitoring staff can report to other parts of the organisation (e.g. security directors, resilience managers).",  # noqa: E501
            "score": 1
        }, {
            "answer": "Monitoring staff are capable of following most of the required workflows.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your monitoring tools can make use of logging that would capture most unsophisticated and untargeted attack types.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your monitoring tools work with most logging data, with some configuration.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Monitoring staff are aware of some essential functions and can manage alerts relating to them.",  # noqa: E501
            "score": 1
        }, {
            "answer": "You have monitoring staff, who are responsible for the analysis, investigation and reporting of monitoring alerts covering both security and performance.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Monitoring staff have defined roles and skills that cover all parts of the monitoring and investigation process.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Monitoring staff follow process and procedures that address all governance reporting requirements, internal and external.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Monitoring staff are empowered to look beyond the fixed process to investigate and understand non-standard threats, by developing their own investigative techniques and making new use of data.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your monitoring tools make use of all logging data collected to pinpoint activity within an incident.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Monitoring staff and tools drive and shape new log data collection and can make wide use of it.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Monitoring staff are aware of the operation of essential functions and related assets and can identify and prioritise alerts or investigations that relate to them.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "C2a System Abnormalities for Attack Detection",  # noqa: E501
        "question": "You define examples of abnormalities in system behaviour that provide practical ways of detecting malicious activity that is otherwise hard to identify.",  # noqa: E501
        "answers": [{
            "answer": "Normal system behaviour is insufficiently understood to be able to use system abnormalities to detect malicious activity.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have no established understanding of what abnormalities to look for that might signify malicious activities.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Normal system behaviour is fully understood to such an extent that searching for system abnormalities is a potentially effective way of detecting malicious activity (e.g. You fully understand which systems should and should not communicate and when).",  # noqa: E501
            "score": 2
        }, {
            "answer": "System abnormality descriptions from past attacks and threat intelligence, on yours and other networks, are used to signify malicious activity.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The system abnormalities you search for consider the nature of attacks likely to impact on the networks and information systems supporting the operation of essential functions.",  # noqa: E501
            "score": 2
        }, {
            "answer": "The system abnormality descriptions you use are updated to reflect changes in your networks and information systems and current threat intelligence.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "C2b Proactive Attack Discovery",  # noqa: E501
        "question": "You use an informed understanding of more sophisticated attack methods and of normal system behaviour to monitor proactively for malicious activity.",  # noqa: E501
        "answers": [{
            "answer": "You do not routinely search for system abnormalities indicative of malicious activity.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You routinely search for system abnormalities indicative of malicious activity on the networks and information systems supporting the operation of your essential function, generating alerts based on the results of such searches.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You have justified confidence in the effectiveness of your searches for system abnormalities indicative of malicious activity.",  # noqa: E501
            "score": 2
        }]
    }],
    "AssessmentD": [{
        "name": "D1a Response Plan",  # noqa: E501
        "question": "You have an up-to-date incident response plan that is grounded in a thorough risk assessment that takes account of your essential function and covers a range of incident scenarios.",  # noqa: E501
        "answers": [{
            "answer": "Your incident response plan is not documented.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your incident response plan does not include your organisation's identified essential function.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your incident response plan is not well understood by relevant staff.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your response plan covers your essential functions.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your response plan comprehensively covers scenarios that are focused on likely impacts of known and well-understood attacks only.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your response plan is understood by all staff who are involved with your organisation's response function.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your response plan is documented and shared with all relevant stakeholders.",  # noqa: E501
            "score": 1
        }, {
            "answer": "Your incident response plan is based on a clear understanding of the security risks to the networks and information systems supporting your essential function.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your incident response plan is comprehensive (i.e. covers the complete lifecycle of an incident, roles and responsibilities, and reporting) and covers likely impacts of both known attack patterns and of possible attacks, previously unseen.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your incident response plan is documented and integrated with wider organisational business and supply chain response plans.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your incident response plan is communicated and understood by the business areas involved with the operation of your essential functions.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "D1 b Response and Recovery Capability",  # noqa: E501
        "question": "You have the capability to enact your incident response plan, including effective limitation of impact on the operation of your essential function. During an incident, you have access to timely information on which to base your response decisions.",  # noqa: E501
        "answers": [{
            "answer": "Inadequate arrangements have been made to make the right resources available to implement your response plan.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Your response team members are not equipped to make good response decisions and put them into effect.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Inadequate back-up mechanisms exist to allow the continued operation of your essential function during an incident.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You understand the resources that will likely be needed to carry out any required response activities, and arrangements are in place to make these resources available.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You understand the types of information that will likely be needed to inform response decisions and arrangements are in place to make this information available.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your response team members have the skills and knowledge required to decide on the response actions necessary to limit harm, and the authority to carry them out.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Back-up mechanisms are available that can be readily activated to allow continued operation of your essential function (although possibly at a reduced level) if primary networks and information systems fail or are unavailable.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Arrangements exist to augment your organisation's incident response capabilities with external support if necessary (e.g. specialist cyber incident responders).",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "D1c Testing and Exercising",  # noqa: E501
        "question": "Your organisation carries out exercises to test response plans, using past incidents that affected your (and other) organisation, and scenarios that draw on threat intelligence and your risk assessment.",  # noqa: E501
        "answers": [{
            "answer": "Exercises test only a discrete part of the process (e.g. that backups are working), but do not consider all areas.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Incident response exercises are not routinely carried out or are carried out in an ad-hoc way.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Outputs from exercises are not fed into the organisation's lessons learned process.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Exercises do not test all parts of the response cycle.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Exercise scenarios are based on incidents experienced by your and other organisations or are composed using experience or threat intelligence.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Exercise scenarios are documented, regularly reviewed, and validated.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Exercises are routinely run, with the findings documented and used to refine incident response plans and protective security, in line with the lessons learned.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Exercises test all parts of your response cycle relating to your essential functions (e.g. restoration of normal function levels).",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "D2a Incident Root Cause Analysis",  # noqa: E501
        "question": "When an incident occurs, steps must be taken to understand its root causes and ensure appropriate remediating action is taken.",  # noqa: E501
        "answers": [{
            "answer": "You are not usually able to resolve incidents to a root cause.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You do not have a formal process for investigating causes.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Root cause analysis is conducted routinely as a key part of your lessons learned activities following an incident.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Your root cause analysis is comprehensive, covering organisational process issues, as well as vulnerabilities in your networks, systems or software.",  # noqa: E501
            "score": 2
        }, {
            "answer": "All relevant incident data is made available to the analysis team to perform root cause analysis.",  # noqa: E501
            "score": 2
        }]
    }, {
        "name": "D2b Using Incidents to Drive Improvements",  # noqa: E501
        "question": "Your organisation uses lessons learned from incidents to improve your security measures.",  # noqa: E501
        "answers": [{
            "answer": "Following incidents, lessons learned are not captured or are limited in scope.",  # noqa: E501
            "score": 0
        }, {
            "answer": "Improvements arising from lessons learned following an incident are not implemented or not given sufficient organisational priority.",  # noqa: E501
            "score": 0
        }, {
            "answer": "You have a documented incident review process/policy which ensures that lessons learned from each incident are identified, captured, and acted upon.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Lessons learned cover issues with reporting, roles, governance, skills and organisational processes as well as technical aspects of networks and information systems.",  # noqa: E501
            "score": 2
        }, {
            "answer": "You use lessons learned to improve security measures, including updating and retesting response plans when necessary.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Security improvements identified as a result of lessons learned are prioritised, with the highest priority improvements completed quickly.",  # noqa: E501
            "score": 2
        }, {
            "answer": "Analysis is fed to senior management and incorporated into risk management and continuous improvement.",  # noqa: E501
            "score": 2
        }]
    }]
}

# Populate the list the questions

demisto.executeCommand("createList", {"listName": "NCSC CAF Assessment", "listData": question_data})
return_results("List created")
