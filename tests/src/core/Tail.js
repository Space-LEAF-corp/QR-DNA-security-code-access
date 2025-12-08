/**
 * Tail: Represents a behavior module in the Fox system
 */
export class Tail {
    name;
    handler;
    constructor(name, handler) {
        this.name = name;
        this.handler = handler;
    }
    async execute(context) {
        await this.handler(context);
    }
}
export class TailRegistry {
    tails = new Map();
    register(tail) {
        this.tails.set(tail.name, tail);
    }
    get(name) {
        return this.tails.get(name);
    }
    getAll() {
        return Array.from(this.tails.values());
    }
    async executeAll(context) {
        for (const tail of this.tails.values()) {
            await tail.execute(context);
        }
    }
}
