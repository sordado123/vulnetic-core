// Coalesce UI work only. Events retain their order and are never replayed as commands.
export function createEventBuffer<T>(deliver:(events:T[])=>void, delay=50) {
  let pending:T[]=[];
  let timer:ReturnType<typeof setTimeout>|undefined;
  let disposed=false;
  const flush=()=>{if(timer)clearTimeout(timer);timer=undefined;if(disposed || !pending.length)return;const events=pending;pending=[];deliver(events);};
  return {
    push(event:T){if(disposed)return;pending.push(event);if(pending.length>=100)flush();else if(!timer)timer=setTimeout(flush,delay);},
    flush,
    dispose(){disposed=true;pending=[];if(timer)clearTimeout(timer);timer=undefined;},
  };
}
