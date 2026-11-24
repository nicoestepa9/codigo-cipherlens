"use client";

import { useCallback, useEffect, useRef, useState } from "react";

interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
}

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [state, setState] = useState<AsyncState<T>>({ data: null, loading: true, error: null });
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const seq = useRef(0);

  const refresh = useCallback(() => {
    const id = ++seq.current;
    setState((s) => ({ ...s, loading: true, error: null }));
    fnRef
      .current()
      .then((data) => {
        if (seq.current === id) setState({ data, loading: false, error: null });
      })
      .catch((error: unknown) => {
        if (seq.current === id) setState({ data: null, loading: false, error: error as Error });
      });
  }, []);

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { ...state, refetch: refresh };
}
