use provenance_mark::ProvenanceMark;

pub trait ProvenanceMarkProvider {
    /// Return the underlying provenance mark.
    fn provenance_mark(&self) -> &ProvenanceMark;

    /// Delegates to `ProvenanceMark::precedes`.
    fn precedes<P: ProvenanceMarkProvider>(&self, next: &P) -> bool {
        self.provenance_mark().precedes(next.provenance_mark())
    }

    /// Delegates to `ProvenanceMark::is_genesis`.
    fn is_genesis(&self) -> bool { self.provenance_mark().is_genesis() }

    /// Delegates to `ProvenanceMark::is_sequence_valid`.
    fn is_sequence_valid<T>(items: &[T]) -> bool
    where
        T: ProvenanceMarkProvider,
    {
        if items.len() < 2 {
            return false;
        }

        if !items
            .first()
            .map(|first| first.is_genesis())
            .unwrap_or(false)
        {
            return false;
        }

        items.windows(2).all(|pair| pair[0].precedes(&pair[1]))
    }
}

impl ProvenanceMarkProvider for ProvenanceMark {
    fn provenance_mark(&self) -> &ProvenanceMark { self }
}
