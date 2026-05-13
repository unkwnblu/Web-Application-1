"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FaXmark } from "react-icons/fa6";
import { IoPhonePortraitOutline } from "react-icons/io5";

const DISMISSED_KEY = "nokslock_app_banner_dismissed";

export default function MobileAppBanner() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (!localStorage.getItem(DISMISSED_KEY)) {
      setVisible(true);
    }
  }, []);

  const dismiss = () => {
    setVisible(false);
    localStorage.setItem(DISMISSED_KEY, "1");
  };

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10, transition: { duration: 0.2 } }}
          transition={{ duration: 0.4 }}
          className="relative overflow-hidden rounded-2xl border border-blue-200 dark:border-blue-800/50 bg-gradient-to-r from-blue-600 via-indigo-600 to-violet-600 p-4 sm:p-5 shadow-lg shadow-blue-500/10 mb-6"
        >
          <div className="absolute inset-0 opacity-10">
            <div className="absolute -right-8 -top-8 h-40 w-40 rounded-full bg-white" />
            <div className="absolute -left-4 -bottom-10 h-32 w-32 rounded-full bg-white" />
          </div>

          <div className="relative flex items-center justify-between gap-4">
            <div className="flex items-center gap-3 sm:gap-4 min-w-0">
              <div className="flex-shrink-0 h-10 w-10 sm:h-12 sm:w-12 rounded-xl bg-white/20 backdrop-blur-sm flex items-center justify-center">
                <IoPhonePortraitOutline className="text-white text-xl sm:text-2xl" />
              </div>
              <div className="min-w-0">
                <p className="font-bold text-white text-sm sm:text-base truncate">
                  Nokslock is coming to mobile!
                </p>
                <p className="text-blue-100 text-xs sm:text-sm mt-0.5 truncate">
                  Access your vault on the go — iOS & Android coming soon.
                </p>
              </div>
            </div>

            <button
              onClick={dismiss}
              className="flex-shrink-0 h-8 w-8 rounded-lg bg-white/15 hover:bg-white/25 flex items-center justify-center transition-colors"
              aria-label="Dismiss banner"
            >
              <FaXmark className="text-white text-sm" />
            </button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
