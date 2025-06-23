import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { v4 as uuidv4 } from 'uuid';
import type { SecurityAlert } from '../types/alerts';

const ajv = new Ajv({
  allErrors: true,
  strict: false,
  coerceTypes: true,
  useDefaults: true
});
addFormats(ajv);

// Define schemas for both formats
const boltSchema = {
  type: 'object',
  required: ['alert_id', 'alert_type', 'timestamp', 'severity'],
  properties: {
    alert_id: { type: 'string' },
    alert_type: { type: 'string' },
    timestamp: { type: 'string', format: 'date-time' },
    severity: { type: 'string' },
    source_ip: { type: 'string' },
    destination_ip: { type: 'string' },
    attack_vector: { type: 'string' },
    detection_method: { type: 'string' },
    alert_message: { type: 'string' },
    status: { type: 'string' },
    category: { type: 'string' }
  },
  additionalProperties: true
};

const stixSchema = {
  type: 'object',
  required: ['alert_id', 'alert_type', 'timestamp', 'severity'],
  properties: {
    alert_id: { type: 'string' },
    alert_type: { type: 'string' },
    timestamp: { type: 'string', format: 'date-time' },
    severity: { type: 'string' },
    source: {
      type: 'object',
      properties: {
        ip: { type: 'string' },
        domain: { type: 'string' },
        user: { type: 'string' }
      },
      required: ['ip']
    },
    target: {
      type: 'object',
      properties: {
        ip: { type: 'string' },
        hostname: { type: 'string' },
        asset_id: { type: 'string' }
      },
      required: ['ip']
    },
    details: {
      type: 'object',
      properties: {
        description: { type: 'string' },
        attack_vector: { type: 'string' },
        indicators: {
          type: 'array',
          items: { type: 'string' }
        }
      }
    },
    status: { type: 'string' }
  },
  additionalProperties: true
};

const validateBolt = ajv.compile(boltSchema);
const validateStix = ajv.compile(stixSchema);

const normalizeAlert = (alert: any): SecurityAlert => {
  // Handle both Bolt.io and STIX formats
  const isBoltFormat = alert.source_ip !== undefined;
  
  return {
    alert_id: alert.alert_id || `ALERT-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Math.floor(Math.random() * 1000).toString().padStart(3, '0')}`,
    alert_type: alert.alert_type || 'Unknown',
    timestamp: alert.timestamp || new Date().toISOString(),
    severity: alert.severity || 'Medium',
    source: {
      ip: isBoltFormat ? alert.source_ip : (alert.source?.ip || '0.0.0.0'),
      domain: isBoltFormat ? undefined : alert.source?.domain,
      user: isBoltFormat ? undefined : alert.source?.user
    },
    target: {
      ip: isBoltFormat ? alert.destination_ip : (alert.target?.ip || '0.0.0.0'),
      hostname: isBoltFormat ? undefined : alert.target?.hostname,
      asset_id: isBoltFormat ? undefined : alert.target?.asset_id
    },
    details: {
      description: isBoltFormat ? alert.alert_message : (alert.details?.description || ''),
      attack_vector: isBoltFormat ? alert.attack_vector : (alert.details?.attack_vector || 'Network'),
      indicators: isBoltFormat ? [] : (alert.details?.indicators || []),
      detection_method: isBoltFormat ? alert.detection_method : undefined
    },
    status: alert.status || 'New',
    category: alert.category
  };
};

export const parseAndValidateInput = (fileContent: string): SecurityAlert[] => {
  try {
    const data = JSON.parse(fileContent);
    const alerts = Array.isArray(data) ? data : [data];
    
    return alerts.map(alert => {
      const boltValid = validateBolt(alert);
      const stixValid = validateStix(alert);
      
      if (!boltValid && !stixValid) {
        const errors = {
          boltErrors: validateBolt.errors,
          stixErrors: validateStix.errors
        };
        console.error('Validation failed for both formats:', errors);
        throw new Error('Alert does not match either Bolt.io or STIX format');
      }
      
      return normalizeAlert(alert);
    });
  } catch (error) {
    console.error('Error processing file:', {
      error: error.message,
      stack: error.stack,
      fileContent: fileContent.substring(0, 200) + '...'
    });
    throw new Error(`Error processing file: ${error.message}`);
  }
};