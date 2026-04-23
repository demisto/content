/**
 * Unit tests for the BrowserManager.
 * Tests lifecycle management, health status, and persistence options.
 * Note: Actual browser launch tests are in integration tests.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { BrowserManager } from '../../src/browser/browser-manager.js';

describe('BrowserManager', () => {
  describe('default construction (persist mode)', () => {
    let manager: BrowserManager;

    beforeEach(() => {
      manager = new BrowserManager();
    });

    it('should not be running initially', () => {
      expect(manager.isRunning()).toBe(false);
    });

    it('should have null PID initially', () => {
      expect(manager.getPid()).toBeNull();
    });

    it('should have zero restart count initially', () => {
      expect(manager.getRestartCount()).toBe(0);
    });

    it('should not report browser as reused initially', () => {
      expect(manager.wasBrowserReused()).toBe(false);
    });
  });

  describe('construction with options', () => {
    it('should accept persist mode options', () => {
      const manager = new BrowserManager({
        stateFilePath: '/tmp/test-state.json',
        persist: true,
      });
      expect(manager.isRunning()).toBe(false);
    });

    it('should accept no-persist mode options', () => {
      const manager = new BrowserManager({
        stateFilePath: '/tmp/test-state.json',
        persist: false,
      });
      expect(manager.isRunning()).toBe(false);
    });
  });

  describe('getHealthStatus', () => {
    it('should return unhealthy status when browser is not running', () => {
      const manager = new BrowserManager();
      const health = manager.getHealthStatus();

      expect(health.isRunning).toBe(false);
      expect(health.pid).toBeNull();
      expect(health.uptime).toBe(0);
      expect(health.contextsCreated).toBe(0);
    });

    it('should not include a locale field', () => {
      const manager = new BrowserManager();
      const health = manager.getHealthStatus();
      expect(health).not.toHaveProperty('locale');
    });
  });

  describe('getBrowser', () => {
    it('should throw when browser is not running', () => {
      const manager = new BrowserManager();
      expect(() => manager.getBrowser()).toThrow('Browser is not running');
    });
  });

  describe('close', () => {
    it('should handle close when browser is not running (persist mode)', async () => {
      const manager = new BrowserManager({ stateFilePath: '/tmp/test.json', persist: true });
      await manager.close();
      expect(manager.isRunning()).toBe(false);
    });

    it('should handle close when browser is not running (no-persist mode)', async () => {
      const manager = new BrowserManager({ stateFilePath: '/tmp/test.json', persist: false });
      await manager.close();
      expect(manager.isRunning()).toBe(false);
    });
  });

  describe('trackContextCreated', () => {
    it('should increment context counter', () => {
      const manager = new BrowserManager();
      manager.trackContextCreated();
      manager.trackContextCreated();
      manager.trackContextCreated();

      const health = manager.getHealthStatus();
      expect(health.contextsCreated).toBe(3);
    });
  });

  describe('setBrowserPid', () => {
    it('should update the PID', () => {
      const manager = new BrowserManager();
      manager.setBrowserPid(12345);
      expect(manager.getPid()).toBe(12345);
    });
  });
});
