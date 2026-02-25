import { describe, it, expect } from 'vitest';

describe('Import debug', () => {
  it('check different import paths', async () => {
    // Path 1: via alias with .js extension (what the service uses)
    try {
      const mod1 = await import('@meritum/shared/constants/platform.constants.js');
      console.log('Alias+.js keys:', Object.keys(mod1));
      console.log('Alias+.js has PracticeStatus:', 'PracticeStatus' in mod1);
    } catch (e: any) {
      console.log('Alias+.js error:', e.message);
    }
    
    // Path 2: via alias without .js extension
    try {
      const mod2 = await import('@meritum/shared/constants/platform.constants');
      console.log('Alias no ext keys:', Object.keys(mod2));
      console.log('Alias no ext has PracticeStatus:', 'PracticeStatus' in mod2);
    } catch (e: any) {
      console.log('Alias no ext error:', e.message);
    }
  });
});
