/**
 * Fox: Main orchestration system
 */
import { TailRegistry } from './Tail.js';
export class Fox {
    config;
    tailRegistry;
    constructor(config = {}) {
        this.config = config;
        this.tailRegistry = new TailRegistry();
    }
    getTailRegistry() {
        return this.tailRegistry;
    }
    getConfig() {
        return { ...this.config };
    }
    async processAction(context) {
        // Execute all registered tail behaviors
        await this.tailRegistry.executeAll(context);
    }
}
