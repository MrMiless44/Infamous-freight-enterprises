module.exports = {
  ci: {
    collect: {
      // Collect from the dist directory
      staticDistDir: './dist',
      // Number of runs per URL
      numberOfRuns: 3,
    },
    assert: {
      // Performance budgets
      assertions: {
        'categories:performance': ['warn', { minScore: 0.8 }],
        'categories:accessibility': ['warn', { minScore: 0.9 }],
        'categories:best-practices': ['warn', { minScore: 0.9 }],
        'categories:seo': ['warn', { minScore: 0.9 }],
      },
    },
    upload: {
      // Upload results to temporary public storage
      target: 'temporary-public-storage',
    },
  },
};
