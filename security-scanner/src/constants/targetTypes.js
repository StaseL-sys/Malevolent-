/**
 * Shared target type metadata used across the application
 */

export const TARGET_TYPES = [
  { 
    id: 'website', 
    name: 'Website', 
    shortName: 'Website Security',
    icon: '🌐', 
    description: 'Scan websites for security headers, SSL, and common vulnerabilities' 
  },
  { 
    id: 'email', 
    name: 'Email', 
    shortName: 'Email Security',
    icon: '✉️', 
    description: 'Check email security (SPF, DKIM, DMARC) configuration' 
  },
  { 
    id: 'server', 
    name: 'Server', 
    shortName: 'Server Security',
    icon: '🖥️', 
    description: 'Assess server security, firewall, and access controls' 
  },
  { 
    id: 'application', 
    name: 'Application', 
    shortName: 'Application Security',
    icon: '📱', 
    description: 'Review application security practices and code safety' 
  },
  { 
    id: 'data', 
    name: 'Data', 
    shortName: 'Data Security',
    icon: '🔐', 
    description: 'Evaluate data protection and encryption practices' 
  },
  { 
    id: 'finance', 
    name: 'Finance', 
    shortName: 'Finance Security',
    icon: '💳', 
    description: 'Assess payment systems, trading platforms, and financial API security' 
  },
  { 
    id: 'iot', 
    name: 'IoT Devices', 
    shortName: 'IoT Security',
    icon: '🏠', 
    description: 'Test smart home devices, industrial IoT, and embedded systems' 
  },
  { 
    id: 'network', 
    name: 'Network', 
    shortName: 'Network Security',
    icon: '🔌', 
    description: 'Evaluate WiFi, VPN, DNS, and network infrastructure security' 
  },
  { 
    id: 'cloud', 
    name: 'Cloud', 
    shortName: 'Cloud Security',
    icon: '☁️', 
    description: 'Review cloud infrastructure, containers, and serverless security' 
  },
  { 
    id: 'threats', 
    name: 'Threat Defense', 
    shortName: 'Modern Threats',
    icon: '🛡️', 
    description: 'Assess defenses against modern threats: ransomware, malware, phishing, and attacks' 
  }
];

/**
 * Target type input field configurations
 */
export const TARGET_INPUT_CONFIG = {
  website: {
    label: 'Website URL',
    placeholder: 'https://example.com'
  },
  email: {
    label: 'Email Domain',
    placeholder: 'example.com'
  },
  server: {
    label: 'Server Address',
    placeholder: '192.168.1.1 or server.example.com'
  },
  application: {
    label: 'Application Name',
    placeholder: 'My Application Name'
  },
  data: {
    label: 'Data Store Name',
    placeholder: 'Database or Data Store Name'
  },
  finance: {
    label: 'Financial System',
    placeholder: 'Payment Gateway or Financial System'
  },
  iot: {
    label: 'IoT Device/System',
    placeholder: 'Smart Device or IoT System'
  },
  network: {
    label: 'Network Name',
    placeholder: 'Network Name or WiFi SSID'
  },
  cloud: {
    label: 'Cloud Environment',
    placeholder: 'Cloud Account or Project Name'
  },
  threats: {
    label: 'Organization/System',
    placeholder: 'Organization or System Name'
  }
};

/**
 * Get target type by ID
 */
export function getTargetTypeById(id) {
  return TARGET_TYPES.find(type => type.id === id);
}

/**
 * Get input configuration for a target type
 */
export function getInputConfig(targetType) {
  return TARGET_INPUT_CONFIG[targetType] || {
    label: 'Target',
    placeholder: 'Enter target'
  };
}
