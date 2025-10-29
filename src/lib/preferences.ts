import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface UIPreferences {
  darkMode: boolean;
  compactView: boolean;
  showStats: boolean;
  preferredSeverityColors: {
    CRITICAL: string;
    HIGH: string;
    MEDIUM: string;
    LOW: string;
    UNKNOWN: string;
  };
  setDarkMode: (enabled: boolean) => void;
  setCompactView: (enabled: boolean) => void;
  setShowStats: (enabled: boolean) => void;
  setSeverityColor: (severity: string, color: string) => void;
}

export const useUIPreferences = create<UIPreferences>()(
  persist(
    (set) => ({
      darkMode: false,
      compactView: false,
      showStats: true,
      preferredSeverityColors: {
        CRITICAL: '#dc2626',
        HIGH: '#ea580c',
        MEDIUM: '#ca8a04',
        LOW: '#16a34a',
        UNKNOWN: '#6b7280'
      },
      setDarkMode: (enabled) => set({ darkMode: enabled }),
      setCompactView: (enabled) => set({ compactView: enabled }),
      setShowStats: (enabled) => set({ showStats: enabled }),
      setSeverityColor: (severity, color) => 
        set((state) => ({
          preferredSeverityColors: {
            ...state.preferredSeverityColors,
            [severity]: color
          }
        }))
    }),
    {
      name: 'ui-preferences'
    }
  )
);